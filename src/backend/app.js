"use strict";

import { readFile } from "node:fs/promises";
import { extname, join, resolve } from "node:path";
import { loadLocalEnv } from "./config/env.js";
import { handleControllerRoutes } from "./routes/controller.js";
import { handleV1Routes } from "./routes/v1.js";
import { getCorsHeaders } from "./security/cors.js";
import { createId } from "./security/crypto.js";
import { checkRateLimit, rateLimitHeaders } from "./security/rateLimiter.js";
import { stateStore } from "./store/stateStore.js";
import { getClientIp, sendError, sendJSON } from "./utils/http.js";
import lemonSqueezyHandler from "../../api/lemon-squeezy/index.js";

loadLocalEnv();

const ROOT_DIR = process.cwd();

const MIME_TYPES = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".ico": "image/x-icon"
};

const STATIC_ALLOWLIST = new Map([
  ["/", "index.html"],
  ["/index.html", "index.html"],
  ["/style.css", "style.css"],
  ["/script.js", "script.js"],
  ["/assets/logo.svg", "assets/logo.svg"],
  ["/assets/favicon.svg", "assets/favicon.svg"],
  ["/dashboard", "dashboard/index.html"],
  ["/dashboard/", "dashboard/index.html"],
  ["/dashboard/index.html", "dashboard/index.html"],
  ["/dashboard/dashboard.css", "dashboard/dashboard.css"],
  ["/dashboard/dashboard.js", "dashboard/dashboard.js"]
]);

const SECTION_REDIRECTS = new Map([
  ["/backend", "/dashboard#providers"],
  ["/backend/", "/dashboard#providers"],
  ["/firebase", "/dashboard#firebase"],
  ["/firebase/", "/dashboard#firebase"],
  ["/google-cloud", "/dashboard#services"],
  ["/google-cloud/", "/dashboard#services"]
]);

async function serveStaticFile(res, relativePath, extraHeaders = {}) {
  const absolutePath = resolve(ROOT_DIR, relativePath);
  if (!absolutePath.startsWith(ROOT_DIR)) {
    return sendError(res, 403, "Access denied.", "FORBIDDEN", extraHeaders);
  }

  try {
    const content = await readFile(absolutePath);
    const ext = extname(absolutePath).toLowerCase();
    res.writeHead(200, {
      "Content-Type": MIME_TYPES[ext] || "application/octet-stream",
      "X-Content-Type-Options": "nosniff",
      ...extraHeaders
    });
    return res.end(content);
  } catch {
    return sendError(res, 404, "Requested static asset not found.", "NOT_FOUND", extraHeaders);
  }
}

export async function handleRequest(req, res) {
  await stateStore.init();

  const startedAt = performance.now();
  const requestId = createId("req");
  const corsHeaders = getCorsHeaders(req);
  const ip = getClientIp(req);

  const url = new URL(
    req.url || "/",
    `http://${req.headers.host || "localhost"}`
  );
  const { pathname } = url;
  const method = (req.method || "GET").toUpperCase();

  if (method === "OPTIONS") {
    res.writeHead(204, {
      ...corsHeaders,
      "X-Request-Id": requestId
    });
    return res.end();
  }

  // Track response status for logging/metrics
  let recordedStatus = 200;
  const originalWriteHead = res.writeHead.bind(res);
  res.writeHead = (statusCode, headersArg, ...rest) => {
    recordedStatus = statusCode;
    if (headersArg && typeof headersArg === "object") {
      return originalWriteHead(
        statusCode,
        {
          ...corsHeaders,
          "X-Request-Id": requestId,
          ...headersArg
        },
        ...rest
      );
    }
    return originalWriteHead(statusCode, headersArg, ...rest);
  };

  try {
    // Rate limiting on API routes
    if (pathname.startsWith("/api")) {
      const isAuth = pathname.startsWith("/api/v1/auth");
      const limit = isAuth
        ? 30
        : Number(stateStore.state.settings.rateLimitPerMin) || 120;
      const rl = checkRateLimit(`${ip}:${isAuth ? "auth" : "api"}`, {
        limit,
        windowMs: 60_000
      });

      if (!rl.allowed) {
        return sendError(
          res,
          429,
          "Rate limit exceeded. Please try again shortly.",
          "RATE_LIMITED",
          rateLimitHeaders(rl)
        );
      }
    }

    // Section redirects from landing page cards
    if (method === "GET" && SECTION_REDIRECTS.has(pathname)) {
      res.writeHead(302, {
        Location: SECTION_REDIRECTS.get(pathname)
      });
      return res.end();
    }

    // Static assets & pages
    if (method === "GET" && STATIC_ALLOWLIST.has(pathname)) {
      return await serveStaticFile(res, STATIC_ALLOWLIST.get(pathname));
    }

    // Health Check
    if (pathname === "/health" && method === "GET") {
      const active = stateStore.getActiveProvider();
      return sendJSON(res, 200, {
        success: true,
        service: "Asbily Controller",
        runtime: `Node.js ${process.version}`,
        status: stateStore.state.settings.maintenanceMode ? "maintenance" : "online",
        activeProvider: active ? active.type : null,
        timestamp: new Date().toISOString()
      });
    }

    // API Info
    if ((pathname === "/api" || pathname === "/api/") && method === "GET") {
      return sendJSON(res, 200, {
        success: true,
        name: "Asbily Controller API",
        version: "1.0.0",
        status: "online",
        gateway: "Cloudflare Workers + Native Node.js",
        endpoints: [
          "/health",
          "/api/v1/auth/*",
          "/api/v1/account/*",
          "/api/v1/user/*",
          "/api/v1/profile/*",
          "/api/v1/security/*",
          "/api/v1/notifications/*",
          "/api/v1/messages/*",
          "/api/v1/payments/*",
          "/api/v1/services/*",
          "/api/v1/storage/*",
          "/api/lemon-squeezy",
          "/api/controller/*"
        ]
      });
    }

    // Lemon Squeezy Endpoint (GET status + POST webhook handler preserved)
    if (pathname === "/api/lemon-squeezy" || pathname === "/api/lemon-squeezy/") {
      if (method === "GET") {
        return sendJSON(res, 200, {
          success: true,
          service: "Lemon Squeezy Integration",
          webhookPath: "/api/lemon-squeezy",
          methods: ["POST"],
          webhookSecretConfigured: Boolean(process.env.LEMONSQUEEZY_WEBHOOK_SECRET),
          storeIdConfigured: Boolean(process.env.LEMONSQUEEZY_STORE_ID)
        });
      }
      return await lemonSqueezyHandler(req, res);
    }

    // Maintenance mode guard for /api/v1/*
    if (
      stateStore.state.settings.maintenanceMode &&
      pathname.startsWith("/api/v1/") &&
      !pathname.startsWith("/api/v1/auth/")
    ) {
      return sendError(
        res,
        503,
        "Controller is currently in maintenance mode.",
        "MAINTENANCE_MODE"
      );
    }

    // API v1 routes
    if (pathname.startsWith("/api/v1/")) {
      return await handleV1Routes(req, res, url, { requestId });
    }

    // Controller management routes
    if (pathname.startsWith("/api/controller/")) {
      return await handleControllerRoutes(req, res, url, { requestId });
    }

    return sendError(res, 404, "Route not found.", "NOT_FOUND");
  } catch (error) {
    const statusCode = error?.statusCode || 500;
    const code = error?.code || "INTERNAL_ERROR";
    const message =
      statusCode >= 500
        ? "Internal server error."
        : error.message || "Bad request.";

    if (statusCode >= 500) {
      console.error("[Asbily Controller Error]", error.message);
    }

    if (!res.headersSent) {
      return sendError(res, statusCode, message, code);
    }
  } finally {
    if (pathname.startsWith("/api") || pathname === "/health") {
      const latencyMs = performance.now() - startedAt;
      const active = stateStore.getActiveProvider();
      stateStore.recordRequest({
        method,
        path: pathname,
        status: recordedStatus,
        latencyMs,
        provider: active ? active.type : "local",
        ip,
        requestId,
        gatewayRouted: Boolean(req.headers["x-forwarded-by"])
      });
    }
  }
}
