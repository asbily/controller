"use strict";

import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { maskSecret } from "../config/env.js";
import {
  createId,
  decryptSecret,
  encryptSecret,
  hashPassword
} from "../security/crypto.js";

const DEFAULT_ROUTES = [
  {
    id: "rt_auth",
    pattern: "/api/v1/auth/*",
    service: "auth",
    targetProvider: "auto",
    fallbackProvider: "",
    authRequired: false,
    rateLimitPerMin: 30,
    timeoutMs: 8000,
    allowSafeFallback: false,
    enabled: true
  },
  {
    id: "rt_account",
    pattern: "/api/v1/account/*",
    service: "account",
    targetProvider: "auto",
    fallbackProvider: "",
    authRequired: true,
    rateLimitPerMin: 60,
    timeoutMs: 8000,
    allowSafeFallback: true,
    enabled: true
  },
  {
    id: "rt_user",
    pattern: "/api/v1/user/*",
    service: "user",
    targetProvider: "auto",
    fallbackProvider: "",
    authRequired: true,
    rateLimitPerMin: 60,
    timeoutMs: 8000,
    allowSafeFallback: true,
    enabled: true
  },
  {
    id: "rt_profile",
    pattern: "/api/v1/profile/*",
    service: "profile",
    targetProvider: "auto",
    fallbackProvider: "",
    authRequired: true,
    rateLimitPerMin: 60,
    timeoutMs: 8000,
    allowSafeFallback: true,
    enabled: true
  },
  {
    id: "rt_security",
    pattern: "/api/v1/security/*",
    service: "security",
    targetProvider: "auto",
    fallbackProvider: "",
    authRequired: true,
    rateLimitPerMin: 40,
    timeoutMs: 8000,
    allowSafeFallback: false,
    enabled: true
  },
  {
    id: "rt_notifications",
    pattern: "/api/v1/notifications/*",
    service: "notifications",
    targetProvider: "auto",
    fallbackProvider: "",
    authRequired: true,
    rateLimitPerMin: 90,
    timeoutMs: 8000,
    allowSafeFallback: true,
    enabled: true
  },
  {
    id: "rt_messages",
    pattern: "/api/v1/messages/*",
    service: "messages",
    targetProvider: "auto",
    fallbackProvider: "",
    authRequired: true,
    rateLimitPerMin: 90,
    timeoutMs: 8000,
    allowSafeFallback: false,
    enabled: true
  },
  {
    id: "rt_payments",
    pattern: "/api/v1/payments/*",
    service: "payments",
    targetProvider: "auto",
    fallbackProvider: "",
    authRequired: false,
    rateLimitPerMin: 60,
    timeoutMs: 10000,
    allowSafeFallback: false,
    enabled: true
  },
  {
    id: "rt_services",
    pattern: "/api/v1/services/*",
    service: "services",
    targetProvider: "auto",
    fallbackProvider: "",
    authRequired: false,
    rateLimitPerMin: 120,
    timeoutMs: 8000,
    allowSafeFallback: true,
    enabled: true
  },
  {
    id: "rt_storage",
    pattern: "/api/v1/storage/*",
    service: "storage",
    targetProvider: "auto",
    fallbackProvider: "",
    authRequired: true,
    rateLimitPerMin: 60,
    timeoutMs: 12000,
    allowSafeFallback: true,
    enabled: true
  }
];

function buildInitialProviders() {
  const now = new Date().toISOString();
  const activeType = (process.env.ACTIVE_PROVIDER || "vercel").toLowerCase();
  const defaultType = (process.env.DEFAULT_PROVIDER || "vercel").toLowerCase();

  const definitions = [
    {
      id: "prov_vercel",
      name: "Vercel Primary",
      type: "vercel",
      backendUrl: (process.env.VERCEL_BACKEND_URL || "").replace(/\/+$/, ""),
      apiKey: process.env.VERCEL_API_KEY || "",
      apiSecret: process.env.VERCEL_API_SECRET || "",
      apiToken: process.env.VERCEL_API_TOKEN || ""
    },
    {
      id: "prov_railway",
      name: "Railway Node Service",
      type: "railway",
      backendUrl: (process.env.RAILWAY_BACKEND_URL || "").replace(/\/+$/, ""),
      apiKey: process.env.RAILWAY_API_KEY || "",
      apiSecret: process.env.RAILWAY_API_SECRET || "",
      apiToken: process.env.RAILWAY_API_TOKEN || ""
    },
    {
      id: "prov_render",
      name: "Render Web Service",
      type: "render",
      backendUrl: (process.env.RENDER_BACKEND_URL || "").replace(/\/+$/, ""),
      apiKey: process.env.RENDER_API_KEY || "",
      apiSecret: process.env.RENDER_API_SECRET || "",
      apiToken: process.env.RENDER_API_TOKEN || ""
    }
  ];

  return definitions.map((def) => ({
    id: def.id,
    name: def.name,
    type: def.type,
    backendUrl: def.backendUrl,
    healthPath: "/health",
    enabled: Boolean(def.backendUrl) || def.type === activeType || def.type === defaultType,
    isDefault: def.type === defaultType,
    isActive: def.type === activeType,
    timeoutMs: 8000,
    customHeaders: {},
    routes: ["/api/v1/*"],
    encryptedApiKey: def.apiKey ? encryptSecret(def.apiKey) : "",
    encryptedApiSecret: def.apiSecret ? encryptSecret(def.apiSecret) : "",
    encryptedApiToken: def.apiToken ? encryptSecret(def.apiToken) : "",
    lastTest: null,
    createdAt: now,
    updatedAt: now
  }));
}

function createInitialState() {
  const now = new Date().toISOString();
  const users = [];

  if (process.env.ASBILY_ADMIN_EMAIL && process.env.ASBILY_ADMIN_PASSWORD) {
    users.push({
      id: createId("usr"),
      email: process.env.ASBILY_ADMIN_EMAIL.trim().toLowerCase(),
      name: "Platform Administrator",
      role: "super_admin",
      status: "active",
      passwordHash: hashPassword(process.env.ASBILY_ADMIN_PASSWORD),
      createdAt: now,
      lastLoginAt: null
    });
  }

  return {
    providers: buildInitialProviders(),
    envVars: [],
    trackedEnvVars: [],
    routes: DEFAULT_ROUTES.map((r) => ({ ...r })),
    users,
    metrics: {
      totalRequests: 0,
      successfulRequests: 0,
      failedRequests: 0,
      gatewayRouted: 0,
      totalLatencyMs: 0,
      providerCounts: {}
    },
    requestLogs: [],
    auditLogs: [
      {
        id: createId("aud"),
        timestamp: now,
        actorEmail: "system",
        actorRole: "system",
        action: "CONTROLLER_INITIALIZED",
        target: "runtime",
        outcome: "success",
        ip: "127.0.0.1"
      }
    ],
    notifications: [
      {
        id: createId("ntf"),
        title: "Asbily Controller Active",
        message: "Native Node.js backend and API Gateway controller initialized.",
        severity: "info",
        read: false,
        createdAt: now
      }
    ],
    messages: [],
    paymentEvents: [],
    settings: {
      gatewayMode: "cloudflare-worker",
      cloudflareGatewayUrl: process.env.CF_GATEWAY_URL || "",
      defaultTimeoutMs: 8000,
      rateLimitPerMin: 120,
      safeIdempotentFallbackOnly: true,
      strictCors: true,
      requireAuthForAdmin: true,
      maintenanceMode: false
    }
  };
}

class ControllerStateStore {
  constructor() {
    this.stateFile = join(process.cwd(), "data", "controller-state.json");
    this.persistenceEnabled = !process.env.VERCEL && process.env.NODE_ENV !== "test";
    this.state = createInitialState();
    this.loaded = false;
  }

  async init() {
    if (this.loaded) return;
    this.loaded = true;

    if (!this.persistenceEnabled) return;

    try {
      const raw = await readFile(this.stateFile, "utf8");
      const saved = JSON.parse(raw);
      if (saved && typeof saved === "object") {
        if (Array.isArray(saved.providers) && saved.providers.length > 0) {
          this.state.providers = saved.providers;
        }
        if (Array.isArray(saved.envVars)) {
          this.state.envVars = saved.envVars;
        }
        if (Array.isArray(saved.trackedEnvVars)) {
          this.state.trackedEnvVars = saved.trackedEnvVars;
        }
        if (Array.isArray(saved.routes) && saved.routes.length > 0) {
          this.state.routes = saved.routes;
        }
        if (Array.isArray(saved.users) && saved.users.length > 0) {
          this.state.users = saved.users;
        }
        if (saved.settings && typeof saved.settings === "object") {
          this.state.settings = { ...this.state.settings, ...saved.settings };
        }
        if (Array.isArray(saved.notifications)) {
          this.state.notifications = saved.notifications;
        }
        if (Array.isArray(saved.messages)) {
          this.state.messages = saved.messages;
        }
      }
    } catch {
      // Fresh instance or ephemeral container; keep initial state
    }
  }

  async persist() {
    if (!this.persistenceEnabled) return;
    try {
      await mkdir(dirname(this.stateFile), { recursive: true });
      const snapshot = {
        providers: this.state.providers,
        envVars: this.state.envVars,
        trackedEnvVars: this.state.trackedEnvVars,
        routes: this.state.routes,
        users: this.state.users,
        settings: this.state.settings,
        notifications: this.state.notifications.slice(0, 50),
        messages: this.state.messages.slice(0, 50)
      };
      await writeFile(this.stateFile, JSON.stringify(snapshot, null, 2), "utf8");
    } catch {
      // Serverless / read-only filesystem fallback: run purely in-memory
      this.persistenceEnabled = false;
    }
  }

  resetForTests() {
    this.persistenceEnabled = false;
    this.state = createInitialState();
    this.loaded = true;
  }

  toPublicProvider(provider) {
    const apiKey = provider.encryptedApiKey ? decryptSecret(provider.encryptedApiKey) : "";
    const apiSecret = provider.encryptedApiSecret ? decryptSecret(provider.encryptedApiSecret) : "";
    const apiToken = provider.encryptedApiToken ? decryptSecret(provider.encryptedApiToken) : "";

    return {
      id: provider.id,
      name: provider.name,
      type: provider.type,
      backendUrl: provider.backendUrl,
      healthPath: provider.healthPath || "/health",
      enabled: Boolean(provider.enabled),
      isDefault: Boolean(provider.isDefault),
      isActive: Boolean(provider.isActive),
      timeoutMs: Number(provider.timeoutMs) || 8000,
      customHeaders: provider.customHeaders || {},
      routes: Array.isArray(provider.routes) ? provider.routes : ["/api/v1/*"],
      credentials: {
        hasApiKey: Boolean(apiKey),
        apiKeyMask: apiKey ? maskSecret(apiKey) : "",
        hasApiSecret: Boolean(apiSecret),
        apiSecretMask: apiSecret ? maskSecret(apiSecret) : "",
        hasApiToken: Boolean(apiToken),
        apiTokenMask: apiToken ? maskSecret(apiToken) : ""
      },
      lastTest: provider.lastTest || null,
      createdAt: provider.createdAt,
      updatedAt: provider.updatedAt
    };
  }

  getProviderCredentials(provider) {
    return {
      apiKey: provider.encryptedApiKey ? decryptSecret(provider.encryptedApiKey) : "",
      apiSecret: provider.encryptedApiSecret ? decryptSecret(provider.encryptedApiSecret) : "",
      apiToken: provider.encryptedApiToken ? decryptSecret(provider.encryptedApiToken) : ""
    };
  }

  toPublicEnvVar(entry) {
    let preview = "";
    if (entry.isSecret) {
      const plain = entry.encryptedValue ? decryptSecret(entry.encryptedValue) : "";
      preview = plain ? maskSecret(plain) : "••••••••";
    } else {
      preview = entry.value || "";
    }

    return {
      id: entry.id,
      scope: entry.scope,
      key: entry.key,
      isSecret: Boolean(entry.isSecret),
      valuePreview: preview,
      configured: Boolean(entry.isSecret ? entry.encryptedValue : entry.value),
      source: "controller-vault",
      updatedAt: entry.updatedAt
    };
  }

  toPublicUser(user) {
    return {
      id: user.id,
      email: user.email,
      name: user.name,
      role: user.role,
      status: user.status,
      createdAt: user.createdAt,
      lastLoginAt: user.lastLoginAt
    };
  }

  recordRequest({ method, path, status, latencyMs, provider = "local", ip = "127.0.0.1", requestId, gatewayRouted = false }) {
    const m = this.state.metrics;
    m.totalRequests += 1;
    if (status >= 200 && status < 400) {
      m.successfulRequests += 1;
    } else if (status >= 400) {
      m.failedRequests += 1;
    }
    if (gatewayRouted) {
      m.gatewayRouted += 1;
    }
    m.totalLatencyMs += Number(latencyMs) || 0;
    m.providerCounts[provider] = (m.providerCounts[provider] || 0) + 1;

    this.state.requestLogs.unshift({
      id: createId("req"),
      timestamp: new Date().toISOString(),
      method,
      path,
      status,
      latencyMs: Math.round(latencyMs),
      provider,
      ip,
      requestId
    });
    if (this.state.requestLogs.length > 250) {
      this.state.requestLogs.length = 250;
    }
  }

  recordAudit({ actorEmail = "anonymous", actorRole = "anonymous", action, target, outcome = "success", ip = "127.0.0.1" }) {
    this.state.auditLogs.unshift({
      id: createId("aud"),
      timestamp: new Date().toISOString(),
      actorEmail,
      actorRole,
      action,
      target,
      outcome,
      ip
    });
    if (this.state.auditLogs.length > 250) {
      this.state.auditLogs.length = 250;
    }
  }

  getActiveProvider() {
    return (
      this.state.providers.find((p) => p.isActive && p.enabled) ||
      this.state.providers.find((p) => p.isDefault && p.enabled) ||
      this.state.providers.find((p) => p.enabled) ||
      null
    );
  }

  getDefaultProvider() {
    return (
      this.state.providers.find((p) => p.isDefault && p.enabled) ||
      this.state.providers.find((p) => p.enabled) ||
      null
    );
  }
}

export const stateStore = new ControllerStateStore();
