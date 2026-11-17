"use strict";

import {
  discoverRuntimeEnvironment,
  isRestrictedInternalEnv,
  maskSecret
} from "../config/env.js";
import {
  forwardToProvider,
  matchRouteRule,
  resolveProvidersForRequest,
  testProviderConnection
} from "../gateway/router.js";
import { authenticateRequest, requireRole } from "../security/auth.js";
import { createId, encryptSecret } from "../security/crypto.js";
import {
  isValidEnvKey,
  readJsonBody,
  sanitizeCustomHeaders,
  validateBackendUrl
} from "../security/validation.js";
import { stateStore } from "../store/stateStore.js";
import { getClientIp, sendError, sendJSON } from "../utils/http.js";

const VALID_PROVIDER_TYPES = new Set(["vercel", "railway", "render", "custom"]);
const VALID_SCOPES = new Set(["gateway", "vercel", "railway", "render", "shared", "firebase", "storage", "payments", "platform", "database", "custom"]);

export async function handleControllerRoutes(req, res, url, context) {
  const { pathname } = url;
  const method = req.method.toUpperCase();
  const ip = getClientIp(req);
  const currentUser = authenticateRequest(req);

  // ==========================================
  // Overview & Monitoring
  // ==========================================
  if (pathname === "/api/controller/overview" && method === "GET") {
    const m = stateStore.state.metrics;
    const activeProvider = stateStore.getActiveProvider();
    const defaultProvider = stateStore.getDefaultProvider();
    const avgLatencyMs =
      m.totalRequests > 0 ? Math.round(m.totalLatencyMs / m.totalRequests) : 0;

    return sendJSON(res, 200, {
      success: true,
      needsBootstrap: stateStore.state.users.length === 0,
      authenticated: Boolean(currentUser),
      user: currentUser,
      metrics: {
        totalRequests: m.totalRequests,
        successfulRequests: m.successfulRequests,
        failedRequests: m.failedRequests,
        gatewayRouted: m.gatewayRouted,
        avgLatencyMs,
        providerCounts: m.providerCounts
      },
      activeProvider: activeProvider ? stateStore.toPublicProvider(activeProvider) : null,
      defaultProvider: defaultProvider ? stateStore.toPublicProvider(defaultProvider) : null,
      providers: stateStore.state.providers.map((p) => stateStore.toPublicProvider(p)),
      apiHealth: {
        status: stateStore.state.settings.maintenanceMode ? "maintenance" : "online",
        runtime: `Node.js ${process.version}`,
        uptimeSeconds: Math.round(process.uptime())
      },
      recentActivity: [
        ...stateStore.state.auditLogs.slice(0, 8).map((a) => ({
          type: "audit",
          timestamp: a.timestamp,
          summary: `${a.action} on ${a.target}`,
          actor: a.actorEmail,
          outcome: a.outcome
        })),
        ...stateStore.state.requestLogs.slice(0, 8).map((r) => ({
          type: "request",
          timestamp: r.timestamp,
          summary: `${r.method} ${r.path} (${r.status})`,
          actor: r.provider,
          outcome: r.status < 400 ? "ok" : "error"
        }))
      ]
        .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
        .slice(0, 12)
    });
  }

  if (pathname === "/api/controller/monitoring" && method === "GET") {
    const m = stateStore.state.metrics;
    return sendJSON(res, 200, {
      success: true,
      monitoring: {
        uptimeSeconds: Math.round(process.uptime()),
        memoryRssMb: Math.round(process.memoryUsage().rss / (1024 * 1024)),
        nodeVersion: process.version,
        totalRequests: m.totalRequests,
        successfulRequests: m.successfulRequests,
        failedRequests: m.failedRequests,
        successRate:
          m.totalRequests > 0
            ? Number(((m.successfulRequests / m.totalRequests) * 100).toFixed(2))
            : 100,
        avgLatencyMs:
          m.totalRequests > 0 ? Math.round(m.totalLatencyMs / m.totalRequests) : 0,
        providerCounts: m.providerCounts,
        providerStatuses: stateStore.state.providers.map((p) => ({
          id: p.id,
          name: p.name,
          type: p.type,
          enabled: p.enabled,
          configured: Boolean(p.backendUrl),
          lastTest: p.lastTest
        }))
      }
    });
  }

  // ==========================================
  // Backend Provider Management
  // ==========================================
  if (pathname === "/api/controller/providers") {
    if (method === "GET") {
      return sendJSON(res, 200, {
        success: true,
        providers: stateStore.state.providers.map((p) => stateStore.toPublicProvider(p))
      });
    }

    if (method === "POST") {
      const actor = requireRole(req, res, "admin");
      if (!actor) return;

      const body = await readJsonBody(req);
      const name = String(body.name || "").trim();
      const type = String(body.type || "custom").trim().toLowerCase();
      const healthPath = String(body.healthPath || "/health").trim() || "/health";
      const timeoutMs = Math.min(Math.max(Number(body.timeoutMs) || 8000, 1000), 30000);

      if (!name) {
        return sendError(res, 400, "Provider name is required.", "VALIDATION_ERROR");
      }
      if (!VALID_PROVIDER_TYPES.has(type)) {
        return sendError(
          res,
          400,
          "Provider type must be vercel, railway, render, or custom.",
          "INVALID_PROVIDER_TYPE"
        );
      }

      let normalizedUrl = "";
      if (body.backendUrl && String(body.backendUrl).trim()) {
        const check = validateBackendUrl(String(body.backendUrl));
        if (!check.valid) {
          return sendError(res, 400, check.error, "INVALID_URL");
        }
        normalizedUrl = check.normalized;
      }

      const now = new Date().toISOString();
      const provider = {
        id: createId("prov"),
        name: name.slice(0, 80),
        type,
        backendUrl: normalizedUrl,
        healthPath: healthPath.startsWith("/") ? healthPath : `/${healthPath}`,
        enabled: body.enabled !== false,
        isDefault: Boolean(body.isDefault),
        isActive: Boolean(body.isActive),
        timeoutMs,
        customHeaders: sanitizeCustomHeaders(body.customHeaders),
        routes: Array.isArray(body.routes) && body.routes.length > 0
          ? body.routes.map((r) => String(r).trim()).filter(Boolean)
          : ["/api/v1/*"],
        encryptedApiKey: body.apiKey ? encryptSecret(String(body.apiKey)) : "",
        encryptedApiSecret: body.apiSecret ? encryptSecret(String(body.apiSecret)) : "",
        encryptedApiToken: body.apiToken ? encryptSecret(String(body.apiToken)) : "",
        lastTest: null,
        createdAt: now,
        updatedAt: now
      };

      if (provider.isActive) {
        for (const p of stateStore.state.providers) p.isActive = false;
      }
      if (provider.isDefault) {
        for (const p of stateStore.state.providers) p.isDefault = false;
      }

      stateStore.state.providers.push(provider);
      stateStore.recordAudit({
        actorEmail: actor.email,
        actorRole: actor.role,
        action: "PROVIDER_CREATED",
        target: `${provider.name} (${provider.type})`,
        outcome: "success",
        ip
      });
      await stateStore.persist();

      return sendJSON(res, 201, {
        success: true,
        provider: stateStore.toPublicProvider(provider)
      });
    }
  }

  // /api/controller/providers/:id & /api/controller/providers/:id/test
  if (pathname.startsWith("/api/controller/providers/")) {
    const parts = pathname.split("/");
    const providerId = parts[4];
    const action = parts[5] || "";
    const provider = stateStore.state.providers.find((p) => p.id === providerId);

    if (!provider) {
      return sendError(res, 404, "Backend provider not found.", "NOT_FOUND");
    }

    if (action === "test" && method === "POST") {
      const actor = requireRole(req, res, "operator");
      if (!actor) return;

      const testResult = await testProviderConnection(provider);
      stateStore.recordAudit({
        actorEmail: actor.email,
        actorRole: actor.role,
        action: "PROVIDER_TESTED",
        target: provider.name,
        outcome: testResult.ok ? "success" : "failed",
        ip
      });

      return sendJSON(res, 200, {
        success: true,
        provider: stateStore.toPublicProvider(provider),
        testResult
      });
    }

    if (!action && (method === "PATCH" || method === "PUT")) {
      const actor = requireRole(req, res, "admin");
      if (!actor) return;

      const body = await readJsonBody(req);

      if (typeof body.name === "string" && body.name.trim()) {
        provider.name = body.name.trim().slice(0, 80);
      }
      if (body.type !== undefined) {
        const nextType = String(body.type).toLowerCase();
        if (!VALID_PROVIDER_TYPES.has(nextType)) {
          return sendError(res, 400, "Invalid provider type.", "INVALID_PROVIDER_TYPE");
        }
        provider.type = nextType;
      }
      if (body.backendUrl !== undefined) {
        const rawUrl = String(body.backendUrl || "").trim();
        if (!rawUrl) {
          provider.backendUrl = "";
        } else {
          const check = validateBackendUrl(rawUrl);
          if (!check.valid) {
            return sendError(res, 400, check.error, "INVALID_URL");
          }
          provider.backendUrl = check.normalized;
        }
      }
      if (typeof body.healthPath === "string" && body.healthPath.trim()) {
        const hp = body.healthPath.trim();
        provider.healthPath = hp.startsWith("/") ? hp : `/${hp}`;
      }
      if (body.timeoutMs !== undefined) {
        provider.timeoutMs = Math.min(Math.max(Number(body.timeoutMs) || 8000, 1000), 30000);
      }
      if (typeof body.enabled === "boolean") {
        provider.enabled = body.enabled;
      }
      if (body.customHeaders !== undefined) {
        provider.customHeaders = sanitizeCustomHeaders(body.customHeaders);
      }
      if (Array.isArray(body.routes)) {
        provider.routes = body.routes.map((r) => String(r).trim()).filter(Boolean);
      }
      if (typeof body.apiKey === "string" && body.apiKey.trim()) {
        provider.encryptedApiKey = encryptSecret(body.apiKey.trim());
      } else if (body.clearApiKey === true) {
        provider.encryptedApiKey = "";
      }
      if (typeof body.apiSecret === "string" && body.apiSecret.trim()) {
        provider.encryptedApiSecret = encryptSecret(body.apiSecret.trim());
      } else if (body.clearApiSecret === true) {
        provider.encryptedApiSecret = "";
      }
      if (typeof body.apiToken === "string" && body.apiToken.trim()) {
        provider.encryptedApiToken = encryptSecret(body.apiToken.trim());
      } else if (body.clearApiToken === true) {
        provider.encryptedApiToken = "";
      }

      if (body.isActive === true) {
        for (const p of stateStore.state.providers) p.isActive = false;
        provider.isActive = true;
        provider.enabled = true;
      }
      if (body.isDefault === true) {
        for (const p of stateStore.state.providers) p.isDefault = false;
        provider.isDefault = true;
        provider.enabled = true;
      }

      provider.updatedAt = new Date().toISOString();
      stateStore.recordAudit({
        actorEmail: actor.email,
        actorRole: actor.role,
        action: "PROVIDER_UPDATED",
        target: provider.name,
        outcome: "success",
        ip
      });
      await stateStore.persist();

      return sendJSON(res, 200, {
        success: true,
        provider: stateStore.toPublicProvider(provider)
      });
    }

    if (!action && method === "DELETE") {
      const actor = requireRole(req, res, "admin");
      if (!actor) return;

      if (stateStore.state.providers.length <= 1) {
        return sendError(
          res,
          400,
          "At least one backend provider configuration must remain.",
          "CANNOT_DELETE_LAST_PROVIDER"
        );
      }

      stateStore.state.providers = stateStore.state.providers.filter(
        (p) => p.id !== providerId
      );
      if (!stateStore.state.providers.some((p) => p.isActive)) {
        stateStore.state.providers[0].isActive = true;
      }
      if (!stateStore.state.providers.some((p) => p.isDefault)) {
        stateStore.state.providers[0].isDefault = true;
      }

      stateStore.recordAudit({
        actorEmail: actor.email,
        actorRole: actor.role,
        action: "PROVIDER_DELETED",
        target: provider.name,
        outcome: "success",
        ip
      });
      await stateStore.persist();

      return sendJSON(res, 200, { success: true });
    }
  }

  // ==========================================
  // Environment Variables Discovery & Secrets Vault
  // ==========================================
  if (pathname === "/api/controller/env") {
    if (method === "GET") {
      const actor = requireRole(req, res, "admin");
      if (!actor) return;

      const discovered = discoverRuntimeEnvironment(stateStore.state.trackedEnvVars);
      return sendJSON(res, 200, {
        success: true,
        runtime: discovered.runtime,
        summary: discovered.summary,
        systemVariables: discovered.systemVariables,
        userVariables: discovered.userVariables,
        trackedVars: stateStore.state.trackedEnvVars,
        vaultVars: stateStore.state.envVars.map((v) => stateStore.toPublicEnvVar(v))
      });
    }

    if (method === "POST") {
      const actor = requireRole(req, res, "admin");
      if (!actor) return;

      const body = await readJsonBody(req);
      const key = String(body.key || "").trim().toUpperCase();
      const scope = String(body.scope || "shared").trim().toLowerCase();
      const isSecret = Boolean(body.isSecret);
      const value = String(body.value ?? "");

      if (!isValidEnvKey(key)) {
        return sendError(
          res,
          400,
          "Environment key must be uppercase alphanumeric with underscores (e.g. VERCEL_BACKEND_URL).",
          "INVALID_ENV_KEY"
        );
      }
      if (!VALID_SCOPES.has(scope)) {
        return sendError(res, 400, "Invalid environment scope.", "INVALID_SCOPE");
      }

      const existing = stateStore.state.envVars.find(
        (v) => v.key === key && v.scope === scope
      );
      const now = new Date().toISOString();

      if (existing) {
        existing.isSecret = isSecret;
        existing.value = isSecret ? "" : value;
        existing.encryptedValue = isSecret ? encryptSecret(value) : "";
        existing.updatedAt = now;
        await stateStore.persist();

        stateStore.recordAudit({
          actorEmail: actor.email,
          actorRole: actor.role,
          action: "ENV_VAR_UPDATED",
          target: `${scope}:${key}`,
          outcome: "success",
          ip
        });

        return sendJSON(res, 200, {
          success: true,
          envVar: stateStore.toPublicEnvVar(existing)
        });
      }

      const created = {
        id: createId("env"),
        scope,
        key,
        isSecret,
        value: isSecret ? "" : value,
        encryptedValue: isSecret ? encryptSecret(value) : "",
        updatedAt: now
      };
      stateStore.state.envVars.push(created);

      stateStore.recordAudit({
        actorEmail: actor.email,
        actorRole: actor.role,
        action: "ENV_VAR_CREATED",
        target: `${scope}:${key}`,
        outcome: "success",
        ip
      });
      await stateStore.persist();

      return sendJSON(res, 201, {
        success: true,
        envVar: stateStore.toPublicEnvVar(created)
      });
    }
  }

  if (pathname === "/api/controller/env/tracked" && method === "POST") {
    const actor = requireRole(req, res, "admin");
    if (!actor) return;

    const body = await readJsonBody(req);
    const key = String(body.key || "").trim().toUpperCase();
    const scope = String(body.scope || "custom").trim().toLowerCase();
    const isSecret = body.isSecret !== false;

    if (!isValidEnvKey(key)) {
      return sendError(
        res,
        400,
        "Variable name must be uppercase alphanumeric with underscores (e.g. CUSTOM_API_URL).",
        "INVALID_ENV_KEY"
      );
    }
    if (isRestrictedInternalEnv(key)) {
      return sendError(
        res,
        400,
        "Internal credential, password, token, private key, or signing secret names cannot be registered for display.",
        "RESTRICTED_ENV_KEY"
      );
    }
    if (!VALID_SCOPES.has(scope)) {
      return sendError(res, 400, "Invalid environment scope.", "INVALID_SCOPE");
    }

    const existing = stateStore.state.trackedEnvVars.find((v) => v.key === key);
    const now = new Date().toISOString();
    if (existing) {
      existing.scope = scope;
      existing.isSecret = isSecret;
      existing.updatedAt = now;
    } else {
      stateStore.state.trackedEnvVars.push({
        key,
        scope,
        isSecret,
        createdAt: now,
        updatedAt: now
      });
    }

    stateStore.recordAudit({
      actorEmail: actor.email,
      actorRole: actor.role,
      action: "ENV_TRACKED_SAVED",
      target: key,
      outcome: "success",
      ip
    });
    await stateStore.persist();

    return sendJSON(res, existing ? 200 : 201, {
      success: true,
      trackedVar: existing || stateStore.state.trackedEnvVars.at(-1)
    });
  }

  if (pathname.startsWith("/api/controller/env/tracked/") && method === "DELETE") {
    const actor = requireRole(req, res, "admin");
    if (!actor) return;
    const key = decodeURIComponent(pathname.split("/")[5] || "").toUpperCase();
    const exists = stateStore.state.trackedEnvVars.some((v) => v.key === key);
    if (!exists) {
      return sendError(res, 404, "Tracked variable name not found.", "NOT_FOUND");
    }
    stateStore.state.trackedEnvVars = stateStore.state.trackedEnvVars.filter(
      (v) => v.key !== key
    );
    stateStore.recordAudit({
      actorEmail: actor.email,
      actorRole: actor.role,
      action: "ENV_TRACKED_DELETED",
      target: key,
      outcome: "success",
      ip
    });
    await stateStore.persist();
    return sendJSON(res, 200, { success: true });
  }

  if (pathname.startsWith("/api/controller/env/") && method === "DELETE") {
    const actor = requireRole(req, res, "admin");
    if (!actor) return;
    const envId = pathname.split("/")[4];
    const target = stateStore.state.envVars.find((v) => v.id === envId);
    if (!target) {
      return sendError(res, 404, "Environment variable not found.", "NOT_FOUND");
    }
    stateStore.state.envVars = stateStore.state.envVars.filter((v) => v.id !== envId);
    stateStore.recordAudit({
      actorEmail: actor.email,
      actorRole: actor.role,
      action: "ENV_VAR_DELETED",
      target: `${target.scope}:${target.key}`,
      outcome: "success",
      ip
    });
    await stateStore.persist();
    return sendJSON(res, 200, { success: true });
  }

  // ==========================================
  // API Gateway Routes Configuration
  // ==========================================
  if (pathname === "/api/controller/routes") {
    if (method === "GET") {
      return sendJSON(res, 200, {
        success: true,
        routes: stateStore.state.routes
      });
    }

    if (method === "POST") {
      const actor = requireRole(req, res, "admin");
      if (!actor) return;

      const body = await readJsonBody(req);
      const pattern = String(body.pattern || "").trim();
      const service = String(body.service || "custom").trim();
      if (!pattern.startsWith("/")) {
        return sendError(res, 400, "Route pattern must start with '/'.", "INVALID_ROUTE");
      }

      const routeRule = {
        id: createId("rt"),
        pattern,
        service,
        targetProvider: String(body.targetProvider || "auto"),
        fallbackProvider: String(body.fallbackProvider || ""),
        authRequired: Boolean(body.authRequired),
        rateLimitPerMin: Math.min(Math.max(Number(body.rateLimitPerMin) || 60, 1), 10000),
        timeoutMs: Math.min(Math.max(Number(body.timeoutMs) || 8000, 1000), 30000),
        allowSafeFallback: body.allowSafeFallback !== false,
        enabled: body.enabled !== false
      };

      stateStore.state.routes.push(routeRule);
      stateStore.recordAudit({
        actorEmail: actor.email,
        actorRole: actor.role,
        action: "ROUTE_CREATED",
        target: pattern,
        outcome: "success",
        ip
      });
      await stateStore.persist();

      return sendJSON(res, 201, { success: true, route: routeRule });
    }
  }

  if (pathname.startsWith("/api/controller/routes/")) {
    const routeId = pathname.split("/")[4];
    const rule = stateStore.state.routes.find((r) => r.id === routeId);
    if (!rule) {
      return sendError(res, 404, "Route rule not found.", "NOT_FOUND");
    }

    if (method === "PATCH") {
      const actor = requireRole(req, res, "admin");
      if (!actor) return;
      const body = await readJsonBody(req);

      if (typeof body.targetProvider === "string") rule.targetProvider = body.targetProvider;
      if (typeof body.fallbackProvider === "string") rule.fallbackProvider = body.fallbackProvider;
      if (typeof body.authRequired === "boolean") rule.authRequired = body.authRequired;
      if (typeof body.allowSafeFallback === "boolean") rule.allowSafeFallback = body.allowSafeFallback;
      if (typeof body.enabled === "boolean") rule.enabled = body.enabled;
      if (body.rateLimitPerMin !== undefined) {
        rule.rateLimitPerMin = Math.min(Math.max(Number(body.rateLimitPerMin) || 60, 1), 10000);
      }
      if (body.timeoutMs !== undefined) {
        rule.timeoutMs = Math.min(Math.max(Number(body.timeoutMs) || 8000, 1000), 30000);
      }

      stateStore.recordAudit({
        actorEmail: actor.email,
        actorRole: actor.role,
        action: "ROUTE_UPDATED",
        target: rule.pattern,
        outcome: "success",
        ip
      });
      await stateStore.persist();
      return sendJSON(res, 200, { success: true, route: rule });
    }

    if (method === "DELETE") {
      const actor = requireRole(req, res, "admin");
      if (!actor) return;
      stateStore.state.routes = stateStore.state.routes.filter((r) => r.id !== routeId);
      await stateStore.persist();
      return sendJSON(res, 200, { success: true });
    }
  }

  // ==========================================
  // Interactive Gateway Dispatch Test
  // ==========================================
  if (pathname === "/api/controller/gateway/dispatch" && method === "POST") {
    const actor = requireRole(req, res, "operator");
    if (!actor) return;

    const body = await readJsonBody(req);
    const targetPath = String(body.path || "/health").trim();
    const targetMethod = String(body.method || "GET").toUpperCase();
    const requestedProviderId = String(body.providerId || "auto");

    if (!targetPath.startsWith("/")) {
      return sendError(res, 400, "Path must start with '/'.", "INVALID_PATH");
    }

    const rule = matchRouteRule(targetPath);
    const { primary, fallback } = resolveProvidersForRequest({
      requestedProviderId,
      routeRule: rule
    });

    if (!primary) {
      return sendError(res, 503, "No enabled backend provider available.", "NO_PROVIDER");
    }

    const result = await forwardToProvider({
      provider: primary,
      fallbackProvider: fallback,
      method: targetMethod,
      pathname: targetPath,
      timeoutMs: rule?.timeoutMs || stateStore.state.settings.defaultTimeoutMs,
      allowSafeFallback: rule?.allowSafeFallback ?? true,
      requestId: context.requestId,
      body:
        targetMethod !== "GET" && targetMethod !== "HEAD" && body.payload
          ? JSON.stringify(body.payload)
          : undefined,
      headers: {
        "content-type": "application/json"
      }
    });

    stateStore.recordRequest({
      method: targetMethod,
      path: targetPath,
      status: result.status,
      latencyMs: result.latencyMs,
      provider: result.provider,
      ip,
      requestId: context.requestId,
      gatewayRouted: true
    });

    return sendJSON(res, 200, {
      success: true,
      dispatch: {
        requestId: context.requestId,
        matchedRule: rule ? rule.pattern : null,
        selectedProvider: primary.type,
        fallbackProvider: fallback ? fallback.type : null,
        fallbackUsed: result.fallbackUsed,
        retryBlockedReason: result.retryBlockedReason,
        status: result.status,
        latencyMs: result.latencyMs,
        response: result.body
      }
    });
  }

  // ==========================================
  // Database, Firebase, Logs, Settings
  // ==========================================
  if (pathname === "/api/controller/database" && method === "GET") {
    const dbUrl = process.env.DATABASE_URL || "";
    const redisUrl = process.env.REDIS_URL || "";
    return sendJSON(res, 200, {
      success: true,
      connections: [
        {
          id: "primary-sql",
          name: "Primary Relational Database",
          envKey: "DATABASE_URL",
          configured: Boolean(dbUrl),
          maskedUri: dbUrl ? maskSecret(dbUrl) : "",
          status: dbUrl ? "configured" : "unconfigured"
        },
        {
          id: "redis-cache",
          name: "Redis / KV Cache",
          envKey: "REDIS_URL",
          configured: Boolean(redisUrl),
          maskedUri: redisUrl ? maskSecret(redisUrl) : "",
          status: redisUrl ? "configured" : "unconfigured"
        },
        {
          id: "controller-state",
          name: "Controller State Store",
          envKey: "local-state",
          configured: true,
          maskedUri: stateStore.persistenceEnabled ? "data/controller-state.json" : "in-memory",
          status: "online"
        }
      ]
    });
  }

  if (pathname === "/api/controller/firebase" && method === "GET") {
    const fbKeys = [
      { key: "FIREBASE_PROJECT_ID", secret: false },
      { key: "FIREBASE_AUTH_DOMAIN", secret: false },
      { key: "FIREBASE_DATABASE_URL", secret: false },
      { key: "FIREBASE_STORAGE_BUCKET", secret: false },
      { key: "FIREBASE_MESSAGING_SENDER_ID", secret: false },
      { key: "FIREBASE_APP_ID", secret: false },
      { key: "FIREBASE_MEASUREMENT_ID", secret: false },
      { key: "FIREBASE_API_KEY", secret: true }
    ];

    const fields = fbKeys.map((item) => {
      const val = process.env[item.key] || "";
      return {
        key: item.key,
        configured: Boolean(val),
        valuePreview: val ? (item.secret ? maskSecret(val) : val) : ""
      };
    });

    return sendJSON(res, 200, {
      success: true,
      configured: Boolean(process.env.FIREBASE_PROJECT_ID && process.env.FIREBASE_API_KEY),
      fields
    });
  }

  if (pathname === "/api/controller/logs" && method === "GET") {
    return sendJSON(res, 200, {
      success: true,
      requestLogs: stateStore.state.requestLogs,
      auditLogs: stateStore.state.auditLogs
    });
  }

  if (pathname === "/api/controller/settings") {
    if (method === "GET") {
      return sendJSON(res, 200, {
        success: true,
        settings: stateStore.state.settings
      });
    }

    if (method === "PATCH") {
      const actor = requireRole(req, res, "admin");
      if (!actor) return;

      const body = await readJsonBody(req);
      const s = stateStore.state.settings;

      if (typeof body.cloudflareGatewayUrl === "string") {
        const trimmed = body.cloudflareGatewayUrl.trim();
        if (trimmed) {
          const check = validateBackendUrl(trimmed);
          if (!check.valid) return sendError(res, 400, check.error, "INVALID_URL");
          s.cloudflareGatewayUrl = check.normalized;
        } else {
          s.cloudflareGatewayUrl = "";
        }
      }
      if (body.defaultTimeoutMs !== undefined) {
        s.defaultTimeoutMs = Math.min(Math.max(Number(body.defaultTimeoutMs) || 8000, 1000), 30000);
      }
      if (body.rateLimitPerMin !== undefined) {
        s.rateLimitPerMin = Math.min(Math.max(Number(body.rateLimitPerMin) || 120, 10), 10000);
      }
      if (typeof body.safeIdempotentFallbackOnly === "boolean") {
        s.safeIdempotentFallbackOnly = body.safeIdempotentFallbackOnly;
      }
      if (typeof body.strictCors === "boolean") {
        s.strictCors = body.strictCors;
      }
      if (typeof body.maintenanceMode === "boolean") {
        s.maintenanceMode = body.maintenanceMode;
      }

      stateStore.recordAudit({
        actorEmail: actor.email,
        actorRole: actor.role,
        action: "SETTINGS_UPDATED",
        target: "controller.settings",
        outcome: "success",
        ip
      });
      await stateStore.persist();

      return sendJSON(res, 200, {
        success: true,
        settings: stateStore.state.settings
      });
    }
  }

  return sendError(res, 404, `Controller route not found: ${pathname}`, "NOT_FOUND");
}
