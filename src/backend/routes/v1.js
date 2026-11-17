"use strict";

import { stateStore } from "../store/stateStore.js";
import {
  authenticateRequest,
  requireAuth,
  requireRole,
  ROLE_HIERARCHY
} from "../security/auth.js";
import {
  createId,
  hashPassword,
  signToken,
  verifyPassword
} from "../security/crypto.js";
import { readJsonBody } from "../security/validation.js";
import { getClientIp, sendError, sendJSON } from "../utils/http.js";
import lemonSqueezyHandler from "../../../api/lemon-squeezy/index.js";
import { ALLOWED_EVENTS, validateEvent } from "../../../api/lemon-squeezy/lemon-squeezy.js";

function setAuthCookieHeader(token, maxAgeSeconds = 60 * 60 * 8) {
  const isProd = process.env.NODE_ENV === "production";
  const parts = [
    `asbily_token=${encodeURIComponent(token)}`,
    "Path=/",
    "HttpOnly",
    "SameSite=Lax",
    `Max-Age=${maxAgeSeconds}`
  ];
  if (isProd) parts.push("Secure");
  return parts.join("; ");
}

function clearAuthCookieHeader() {
  return "asbily_token=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0";
}

export async function handleV1Routes(req, res, url, context) {
  const { pathname } = url;
  const method = req.method.toUpperCase();
  const ip = getClientIp(req);

  // ==========================================
  // /api/v1/auth/*
  // ==========================================
  if (pathname === "/api/v1/auth/session" && method === "GET") {
    const user = authenticateRequest(req);
    return sendJSON(res, 200, {
      success: true,
      authenticated: Boolean(user),
      needsBootstrap: stateStore.state.users.length === 0,
      user
    });
  }

  if (pathname === "/api/v1/auth/bootstrap" && method === "POST") {
    if (stateStore.state.users.length > 0) {
      return sendError(
        res,
        409,
        "Initial administrator already exists. Please sign in.",
        "BOOTSTRAP_LOCKED"
      );
    }

    const body = await readJsonBody(req);
    const email = String(body.email || "").trim().toLowerCase();
    const password = String(body.password || "");
    const name = String(body.name || "Controller Admin").trim();

    if (!email || !email.includes("@")) {
      return sendError(res, 400, "Valid email address is required.", "INVALID_EMAIL");
    }
    if (password.length < 8) {
      return sendError(
        res,
        400,
        "Password must be at least 8 characters long.",
        "WEAK_PASSWORD"
      );
    }

    const now = new Date().toISOString();
    const user = {
      id: createId("usr"),
      email,
      name,
      role: "super_admin",
      status: "active",
      passwordHash: hashPassword(password),
      createdAt: now,
      lastLoginAt: now
    };

    stateStore.state.users.push(user);
    stateStore.recordAudit({
      actorEmail: email,
      actorRole: user.role,
      action: "ADMIN_BOOTSTRAPPED",
      target: user.id,
      outcome: "success",
      ip
    });
    await stateStore.persist();

    const token = signToken({ sub: user.id, role: user.role, email: user.email });
    return sendJSON(
      res,
      201,
      {
        success: true,
        token,
        user: stateStore.toPublicUser(user)
      },
      { "Set-Cookie": setAuthCookieHeader(token) }
    );
  }

  if (pathname === "/api/v1/auth/login" && method === "POST") {
    const body = await readJsonBody(req);
    const email = String(body.email || "").trim().toLowerCase();
    const password = String(body.password || "");

    const user = stateStore.state.users.find((u) => u.email === email);
    if (!user || !verifyPassword(password, user.passwordHash)) {
      stateStore.recordAudit({
        actorEmail: email || "unknown",
        actorRole: "anonymous",
        action: "AUTH_LOGIN_FAILED",
        target: email || "unknown",
        outcome: "denied",
        ip
      });
      return sendError(res, 401, "Invalid email or password.", "INVALID_CREDENTIALS");
    }

    if (user.status !== "active") {
      return sendError(res, 403, "User account is disabled.", "ACCOUNT_DISABLED");
    }

    user.lastLoginAt = new Date().toISOString();
    stateStore.recordAudit({
      actorEmail: user.email,
      actorRole: user.role,
      action: "AUTH_LOGIN",
      target: user.id,
      outcome: "success",
      ip
    });
    await stateStore.persist();

    const token = signToken({ sub: user.id, role: user.role, email: user.email });
    return sendJSON(
      res,
      200,
      {
        success: true,
        token,
        user: stateStore.toPublicUser(user)
      },
      { "Set-Cookie": setAuthCookieHeader(token) }
    );
  }

  if (pathname === "/api/v1/auth/logout" && method === "POST") {
    return sendJSON(
      res,
      200,
      { success: true, message: "Signed out." },
      { "Set-Cookie": clearAuthCookieHeader() }
    );
  }

  // ==========================================
  // /api/v1/account/* & /api/v1/profile/*
  // ==========================================
  if (pathname === "/api/v1/account" && method === "GET") {
    const actor = requireAuth(req, res);
    if (!actor) return;
    return sendJSON(res, 200, {
      success: true,
      account: {
        id: actor.id,
        email: actor.email,
        name: actor.name,
        role: actor.role,
        platformUrls: {
          account: process.env.ASBILY_ACCOUNT_URL || null,
          controller: process.env.ASBILY_CONTROLLER_URL || null,
          myAccount: process.env.ASBILY_MYACCOUNT_URL || null
        }
      }
    });
  }

  if (pathname === "/api/v1/profile" && (method === "GET" || method === "PATCH")) {
    const actor = requireAuth(req, res);
    if (!actor) return;
    const record = stateStore.state.users.find((u) => u.id === actor.id);
    if (method === "PATCH") {
      const body = await readJsonBody(req);
      if (typeof body.name === "string" && body.name.trim()) {
        record.name = body.name.trim().slice(0, 80);
      }
      await stateStore.persist();
    }
    return sendJSON(res, 200, {
      success: true,
      profile: stateStore.toPublicUser(record)
    });
  }

  // ==========================================
  // /api/v1/user/* (Users & RBAC management)
  // ==========================================
  if (pathname === "/api/v1/user" || pathname === "/api/v1/users") {
    if (method === "GET") {
      const actor = requireAuth(req, res);
      if (!actor) return;
      return sendJSON(res, 200, {
        success: true,
        users: stateStore.state.users.map((u) => stateStore.toPublicUser(u))
      });
    }

    if (method === "POST") {
      const actor = requireRole(req, res, "admin");
      if (!actor) return;

      const body = await readJsonBody(req);
      const email = String(body.email || "").trim().toLowerCase();
      const name = String(body.name || "").trim();
      const password = String(body.password || "");
      const role = String(body.role || "viewer").toLowerCase();

      if (!email || !email.includes("@")) {
        return sendError(res, 400, "Valid email is required.", "INVALID_EMAIL");
      }
      if (!ROLE_HIERARCHY[role]) {
        return sendError(res, 400, "Invalid role specified.", "INVALID_ROLE");
      }
      if (role === "super_admin" && actor.role !== "super_admin") {
        return sendError(res, 403, "Only super_admin can assign super_admin.", "FORBIDDEN");
      }
      if (password.length < 8) {
        return sendError(res, 400, "Password must be at least 8 characters.", "WEAK_PASSWORD");
      }
      if (stateStore.state.users.some((u) => u.email === email)) {
        return sendError(res, 409, "User with this email already exists.", "USER_EXISTS");
      }

      const newUser = {
        id: createId("usr"),
        email,
        name: name || email.split("@")[0],
        role,
        status: "active",
        passwordHash: hashPassword(password),
        createdAt: new Date().toISOString(),
        lastLoginAt: null
      };

      stateStore.state.users.push(newUser);
      stateStore.recordAudit({
        actorEmail: actor.email,
        actorRole: actor.role,
        action: "USER_CREATED",
        target: `${email} (${role})`,
        outcome: "success",
        ip
      });
      await stateStore.persist();

      return sendJSON(res, 201, {
        success: true,
        user: stateStore.toPublicUser(newUser)
      });
    }
  }

  if (pathname.startsWith("/api/v1/user/") || pathname.startsWith("/api/v1/users/")) {
    const userId = pathname.split("/")[4];
    const target = stateStore.state.users.find((u) => u.id === userId);
    if (!target) {
      return sendError(res, 404, "User not found.", "NOT_FOUND");
    }

    if (method === "PATCH") {
      const actor = requireRole(req, res, "admin");
      if (!actor) return;
      const body = await readJsonBody(req);

      if (body.role !== undefined) {
        const nextRole = String(body.role).toLowerCase();
        if (!ROLE_HIERARCHY[nextRole]) {
          return sendError(res, 400, "Invalid role.", "INVALID_ROLE");
        }
        if (nextRole === "super_admin" && actor.role !== "super_admin") {
          return sendError(res, 403, "Only super_admin can promote to super_admin.", "FORBIDDEN");
        }
        target.role = nextRole;
      }

      if (body.status === "active" || body.status === "disabled") {
        if (target.id === actor.id && body.status === "disabled") {
          return sendError(res, 400, "Cannot disable your own active session.", "INVALID_ACTION");
        }
        target.status = body.status;
      }

      if (typeof body.name === "string" && body.name.trim()) {
        target.name = body.name.trim().slice(0, 80);
      }

      stateStore.recordAudit({
        actorEmail: actor.email,
        actorRole: actor.role,
        action: "USER_UPDATED",
        target: `${target.email} (${target.role}/${target.status})`,
        outcome: "success",
        ip
      });
      await stateStore.persist();

      return sendJSON(res, 200, {
        success: true,
        user: stateStore.toPublicUser(target)
      });
    }

    if (method === "DELETE") {
      const actor = requireRole(req, res, "admin");
      if (!actor) return;
      if (target.id === actor.id) {
        return sendError(res, 400, "Cannot delete your own account.", "INVALID_ACTION");
      }
      stateStore.state.users = stateStore.state.users.filter((u) => u.id !== userId);
      stateStore.recordAudit({
        actorEmail: actor.email,
        actorRole: actor.role,
        action: "USER_DELETED",
        target: target.email,
        outcome: "success",
        ip
      });
      await stateStore.persist();
      return sendJSON(res, 200, { success: true });
    }
  }

  // ==========================================
  // /api/v1/security/*
  // ==========================================
  if (pathname === "/api/v1/security" && method === "GET") {
    return sendJSON(res, 200, {
      success: true,
      policies: {
        secretEncryption: "AES-256-GCM",
        passwordHashing: "scrypt",
        tokenSigning: "HMAC-SHA256",
        maxBodySizeBytes: 1048576,
        rateLimitPerMin: stateStore.state.settings.rateLimitPerMin,
        strictCors: stateStore.state.settings.strictCors,
        idempotentFallbackOnly: stateStore.state.settings.safeIdempotentFallbackOnly,
        rbacRoles: Object.keys(ROLE_HIERARCHY)
      },
      auditLogs: stateStore.state.auditLogs.slice(0, 50)
    });
  }

  // ==========================================
  // /api/v1/notifications/*
  // ==========================================
  if (pathname === "/api/v1/notifications" && method === "GET") {
    return sendJSON(res, 200, {
      success: true,
      notifications: stateStore.state.notifications
    });
  }

  if (pathname === "/api/v1/notifications/read" && method === "POST") {
    const actor = requireAuth(req, res);
    if (!actor) return;
    for (const n of stateStore.state.notifications) {
      n.read = true;
    }
    await stateStore.persist();
    return sendJSON(res, 200, { success: true });
  }

  // ==========================================
  // /api/v1/messages/*
  // ==========================================
  if (pathname === "/api/v1/messages") {
    if (method === "GET") {
      return sendJSON(res, 200, {
        success: true,
        messages: stateStore.state.messages
      });
    }
    if (method === "POST") {
      const actor = requireAuth(req, res);
      if (!actor) return;
      const body = await readJsonBody(req);
      const subject = String(body.subject || "").trim();
      const content = String(body.content || "").trim();
      if (!subject || !content) {
        return sendError(res, 400, "Subject and content are required.", "VALIDATION_ERROR");
      }
      const msg = {
        id: createId("msg"),
        from: actor.email,
        subject: subject.slice(0, 120),
        content: content.slice(0, 2000),
        createdAt: new Date().toISOString()
      };
      stateStore.state.messages.unshift(msg);
      await stateStore.persist();
      return sendJSON(res, 201, { success: true, message: msg });
    }
  }

  // ==========================================
  // /api/v1/payments/* (Lemon Squeezy Integration)
  // ==========================================
  if (pathname === "/api/v1/payments" && method === "GET") {
    return sendJSON(res, 200, {
      success: true,
      provider: "lemon-squeezy",
      configured: {
        apiKey: Boolean(process.env.LEMONSQUEEZY_API_KEY),
        apiUrl: process.env.LEMONSQUEEZY_API_URL || "https://api.lemonsqueezy.com/v1",
        storeId: Boolean(process.env.LEMONSQUEEZY_STORE_ID),
        webhookSecret: Boolean(process.env.LEMONSQUEEZY_WEBHOOK_SECRET),
        membershipVariantId: Boolean(process.env.LEMONSQUEEZY_MEMBERSHIP_VARIANT_ID),
        premiumVariantId: Boolean(process.env.LEMONSQUEEZY_PREMIUM_VARIANT_ID)
      },
      allowedEvents: Array.from(ALLOWED_EVENTS),
      webhookEndpoint: "/api/lemon-squeezy",
      recentEvents: stateStore.state.paymentEvents.slice(0, 25)
    });
  }

  if (pathname === "/api/v1/payments/validate-event" && method === "POST") {
    const actor = requireRole(req, res, "operator");
    if (!actor) return;
    const payload = await readJsonBody(req);
    const validation = validateEvent(payload);
    return sendJSON(res, 200, {
      success: true,
      validation
    });
  }

  if (pathname === "/api/v1/payments/webhook" && method === "POST") {
    return lemonSqueezyHandler(req, res);
  }

  // ==========================================
  // /api/v1/services/*
  // ==========================================
  if (pathname === "/api/v1/services" && method === "GET") {
    const active = stateStore.getActiveProvider();
    return sendJSON(res, 200, {
      success: true,
      services: [
        {
          id: "gateway",
          name: "Cloudflare Workers Gateway",
          status: stateStore.state.settings.cloudflareGatewayUrl ? "configured" : "ready",
          endpoint: stateStore.state.settings.cloudflareGatewayUrl || "/api/v1/*"
        },
        {
          id: "backend",
          name: "Native Node.js Backend",
          status: "online",
          activeProvider: active ? active.type : "none"
        },
        {
          id: "firebase",
          name: "Firebase",
          status: process.env.FIREBASE_PROJECT_ID ? "configured" : "unconfigured"
        },
        {
          id: "google-cloud",
          name: "Google Cloud / Workers",
          status: process.env.FIREBASE_PROJECT_ID ? "configured" : "standby"
        },
        {
          id: "storage",
          name: "Cloudflare R2 Storage",
          status: process.env.R2_BUCKET_NAME ? "configured" : "planned"
        },
        {
          id: "payments",
          name: "Lemon Squeezy",
          status: process.env.LEMONSQUEEZY_WEBHOOK_SECRET ? "configured" : "unconfigured"
        }
      ],
      requestId: context.requestId
    });
  }

  // ==========================================
  // /api/v1/storage/* (Cloudflare R2 Ready)
  // ==========================================
  if (pathname === "/api/v1/storage" && method === "GET") {
    return sendJSON(res, 200, {
      success: true,
      provider: "cloudflare-r2",
      configured: {
        accountId: Boolean(process.env.R2_ACCOUNT_ID),
        bucketName: process.env.R2_BUCKET_NAME || "",
        endpoint: process.env.R2_ENDPOINT || "",
        accessKeyId: Boolean(process.env.R2_ACCESS_KEY_ID),
        secretAccessKey: Boolean(process.env.R2_SECRET_ACCESS_KEY)
      },
      bindingName: "ASBILY_STORAGE",
      status: process.env.R2_BUCKET_NAME && process.env.R2_ACCESS_KEY_ID ? "ready" : "awaiting-credentials"
    });
  }

  return sendError(res, 404, `API v1 route not found: ${pathname}`, "NOT_FOUND");
}
