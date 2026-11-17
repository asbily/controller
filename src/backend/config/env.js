"use strict";

import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import crypto from "node:crypto";

const ENV_LOADED_FLAG = Symbol.for("asbily.env.loaded");

// Ephemeral fallback secrets for local development when env vars are unset.
// Generated dynamically per process — never hardcoded.
const ephemeralSessionSecret = crypto.randomBytes(32).toString("hex");
const ephemeralEncryptionKey = crypto.randomBytes(32);

export function loadLocalEnv(rootDir = process.cwd()) {
  if (globalThis[ENV_LOADED_FLAG]) {
    return;
  }
  globalThis[ENV_LOADED_FLAG] = true;

  const envPath = join(rootDir, ".env");
  if (!existsSync(envPath)) {
    return;
  }

  try {
    const content = readFileSync(envPath, "utf8");
    for (const rawLine of content.split(/\r?\n/)) {
      const line = rawLine.trim();
      if (!line || line.startsWith("#")) continue;
      const eqIndex = line.indexOf("=");
      if (eqIndex <= 0) continue;

      const key = line.slice(0, eqIndex).trim();
      let value = line.slice(eqIndex + 1).trim();

      if (
        (value.startsWith('"') && value.endsWith('"')) ||
        (value.startsWith("'") && value.endsWith("'"))
      ) {
        value = value.slice(1, -1);
      }

      if (!(key in process.env)) {
        process.env[key] = value;
      }
    }
  } catch (err) {
    console.warn("[Asbily Env] Could not parse .env file:", err.message);
  }
}

export function getSessionSecret() {
  return process.env.CONTROLLER_SESSION_SECRET || ephemeralSessionSecret;
}

export function getEncryptionKey() {
  const configured = process.env.CONTROLLER_ENCRYPTION_KEY;
  if (configured && configured.length >= 16) {
    return crypto.createHash("sha256").update(configured).digest();
  }
  return ephemeralEncryptionKey;
}

export function maskSecret(value) {
  if (value === undefined || value === null) return "";
  const str = String(value);
  if (!str) return "";
  return "••••••••";
}

// Known user-configured platform & integration environment variables
export const ENV_CATALOG = [
  { key: "ASBILY_ACCOUNT_URL", scope: "platform", isSecret: false },
  { key: "ASBILY_CONTROLLER_URL", scope: "platform", isSecret: false },
  { key: "ASBILY_MYACCOUNT_URL", scope: "platform", isSecret: false },
  { key: "CF_GATEWAY_URL", scope: "gateway", isSecret: false },
  { key: "ACTIVE_PROVIDER", scope: "gateway", isSecret: false },
  { key: "DEFAULT_PROVIDER", scope: "gateway", isSecret: false },
  { key: "ALLOWED_ORIGINS", scope: "gateway", isSecret: false },
  { key: "VERCEL_BACKEND_URL", scope: "vercel", isSecret: false },
  { key: "VERCEL_API_KEY", scope: "vercel", isSecret: true },
  { key: "VERCEL_API_SECRET", scope: "vercel", isSecret: true },
  { key: "RAILWAY_BACKEND_URL", scope: "railway", isSecret: false },
  { key: "RAILWAY_API_KEY", scope: "railway", isSecret: true },
  { key: "RAILWAY_API_SECRET", scope: "railway", isSecret: true },
  { key: "RENDER_BACKEND_URL", scope: "render", isSecret: false },
  { key: "RENDER_API_KEY", scope: "render", isSecret: true },
  { key: "RENDER_API_SECRET", scope: "render", isSecret: true },
  { key: "DATABASE_URL", scope: "database", isSecret: true },
  { key: "REDIS_URL", scope: "database", isSecret: true },
  { key: "FIREBASE_API_KEY", scope: "firebase", isSecret: true },
  { key: "FIREBASE_APP_ID", scope: "firebase", isSecret: false },
  { key: "FIREBASE_AUTH_DOMAIN", scope: "firebase", isSecret: false },
  { key: "FIREBASE_DATABASE_URL", scope: "firebase", isSecret: false },
  { key: "FIREBASE_MEASUREMENT_ID", scope: "firebase", isSecret: false },
  { key: "FIREBASE_MESSAGING_SENDER_ID", scope: "firebase", isSecret: false },
  { key: "FIREBASE_PROJECT_ID", scope: "firebase", isSecret: false },
  { key: "FIREBASE_STORAGE_BUCKET", scope: "firebase", isSecret: false },
  { key: "R2_ACCOUNT_ID", scope: "storage", isSecret: false },
  { key: "R2_BUCKET_NAME", scope: "storage", isSecret: false },
  { key: "R2_ACCESS_KEY_ID", scope: "storage", isSecret: true },
  { key: "R2_SECRET_ACCESS_KEY", scope: "storage", isSecret: true },
  { key: "R2_ENDPOINT", scope: "storage", isSecret: false },
  { key: "LEMONSQUEEZY_API_KEY", scope: "payments", isSecret: true },
  { key: "LEMONSQUEEZY_API_URL", scope: "payments", isSecret: false },
  { key: "LEMONSQUEEZY_MEMBERSHIP_VARIANT_ID", scope: "payments", isSecret: false },
  { key: "LEMONSQUEEZY_PREMIUM_VARIANT_ID", scope: "payments", isSecret: false },
  { key: "LEMONSQUEEZY_STORE_ID", scope: "payments", isSecret: false },
  { key: "LEMONSQUEEZY_WEBHOOK_SECRET", scope: "payments", isSecret: true }
];

const CATALOG_MAP = new Map(ENV_CATALOG.map((entry) => [entry.key, entry]));

// Internal credentials, passwords, tokens, private keys, and signing secrets
// MUST NEVER be displayed or returned by any discovery endpoint.
const RESTRICTED_INTERNAL_KEY_PATTERN =
  /(password|passphrase|private[_-]?key|signing[_-]?secret|session[_-]?secret|encryption[_-]?key|oidc[_-]?token|auth[_-]?token|access[_-]?token|refresh[_-]?token|bearer|credential|cookie[_-]?secret|npm_token|github_token|gh_token|service_role|jwt_secret|api_token|admin_token|root_key|ssh_key|gpg_key)/i;

const RESTRICTED_VALUE_PATTERN =
  /(-----BEGIN\s+[A-Z0-9\s]*PRIVATE\s+KEY-----|ghp_[A-Za-z0-9]{20,}|AIza[0-9A-Za-z_-]{30,}|sk_live_[0-9A-Za-z]{16,})/;

const SECRET_KEY_PATTERN =
  /(secret|api[_-]?key|apikey|webhook|salt|hash|cert|database_url|redis_url|mongo|dsn|connection_string)/i;

const SYSTEM_KEY_PREFIXES = [
  "VERCEL",
  "RAILWAY",
  "RENDER",
  "NODE_",
  "NPM_",
  "HOST",
  "PORT",
  "PATH",
  "HOME",
  "PWD",
  "SHELL",
  "USER",
  "LANG",
  "LC_",
  "TZ",
  "TERM",
  "HOSTNAME",
  "CI",
  "K_SERVICE",
  "K_REVISION",
  "K_CONFIGURATION",
  "GOOGLE_CLOUD_",
  "CLOUD_RUN_",
  "XDG_",
  "SHLVL",
  "TMPDIR",
  "INIT_CWD",
  "COLOR",
  "EDITOR"
];

const PROVIDER_SYSTEM_EXPECTED_KEYS = {
  vercel: [
    "VERCEL",
    "VERCEL_ENV",
    "VERCEL_URL",
    "VERCEL_REGION",
    "VERCEL_BRANCH_URL",
    "VERCEL_GIT_PROVIDER",
    "VERCEL_GIT_REPO_SLUG",
    "VERCEL_GIT_COMMIT_REF",
    "VERCEL_GIT_COMMIT_SHA"
  ],
  railway: [
    "RAILWAY_ENVIRONMENT",
    "RAILWAY_ENVIRONMENT_NAME",
    "RAILWAY_PROJECT_ID",
    "RAILWAY_PROJECT_NAME",
    "RAILWAY_SERVICE_ID",
    "RAILWAY_SERVICE_NAME",
    "RAILWAY_PUBLIC_DOMAIN",
    "RAILWAY_GIT_BRANCH",
    "PORT"
  ],
  render: [
    "RENDER",
    "RENDER_SERVICE_ID",
    "RENDER_SERVICE_NAME",
    "RENDER_SERVICE_TYPE",
    "RENDER_EXTERNAL_URL",
    "RENDER_EXTERNAL_HOSTNAME",
    "RENDER_INSTANCE_ID",
    "RENDER_GIT_BRANCH",
    "PORT"
  ],
  nodejs: ["NODE_ENV", "PORT", "HOST"]
};

export function isRestrictedInternalEnv(key, value = "") {
  if (RESTRICTED_INTERNAL_KEY_PATTERN.test(key)) {
    return true;
  }
  if (typeof value === "string" && RESTRICTED_VALUE_PATTERN.test(value)) {
    return true;
  }
  return false;
}

export function isSecretEnv(key, value = "", explicitSecret) {
  if (explicitSecret === true) return true;
  if (SECRET_KEY_PATTERN.test(key)) return true;
  if (typeof value === "string" && /^[a-z]+:\/\/[^/\s:@]+:[^/\s@]+@/i.test(value)) {
    return true;
  }
  return false;
}

function isSystemManagedKey(key) {
  if (CATALOG_MAP.has(key)) return false;
  if (
    key === "VERCEL_BACKEND_URL" ||
    key === "RAILWAY_BACKEND_URL" ||
    key === "RENDER_BACKEND_URL"
  ) {
    return false;
  }
  return SYSTEM_KEY_PREFIXES.some(
    (prefix) => key === prefix || key.startsWith(prefix)
  );
}

function inferScope(key) {
  const catalogEntry = CATALOG_MAP.get(key);
  if (catalogEntry) return catalogEntry.scope;
  if (key.startsWith("VERCEL_")) return "vercel";
  if (key.startsWith("RAILWAY_")) return "railway";
  if (key.startsWith("RENDER_")) return "render";
  if (key.startsWith("FIREBASE_")) return "firebase";
  if (key.startsWith("R2_")) return "storage";
  if (key.startsWith("LEMONSQUEEZY_")) return "payments";
  if (key.startsWith("ASBILY_")) return "platform";
  if (key.startsWith("CF_") || key.startsWith("GATEWAY_")) return "gateway";
  if (isSystemManagedKey(key)) return "system";
  return "custom";
}

function sanitizeSafePreview(value) {
  const str = String(value ?? "").trim();
  if (!str) return "";
  // Redact embedded URL credentials even if key name wasn't flagged
  const cleaned = str.replace(/([a-z]+:\/\/)([^/\s:@]+):([^/\s@]+)@/gi, "$1••••:••••@");
  return cleaned.length > 120 ? `${cleaned.slice(0, 117)}...` : cleaned;
}

export function detectRuntimeProvider() {
  if (
    process.env.VERCEL === "1" ||
    Boolean(process.env.VERCEL_ENV || process.env.VERCEL_REGION || process.env.VERCEL_URL)
  ) {
    return {
      provider: "vercel",
      label: "Vercel Serverless (Node.js)",
      region: process.env.VERCEL_REGION || null,
      environment: process.env.VERCEL_ENV || process.env.NODE_ENV || "production",
      isolationNote:
        "Reads only current Vercel runtime process.env. Vercel cannot read Railway, Render, or Cloudflare Worker bindings."
    };
  }

  if (
    Boolean(
      process.env.RAILWAY_ENVIRONMENT ||
        process.env.RAILWAY_ENVIRONMENT_NAME ||
        process.env.RAILWAY_PROJECT_ID ||
        process.env.RAILWAY_SERVICE_ID
    )
  ) {
    return {
      provider: "railway",
      label: "Railway Container (Node.js)",
      region: process.env.RAILWAY_REPLICA_REGION || null,
      environment:
        process.env.RAILWAY_ENVIRONMENT_NAME ||
        process.env.RAILWAY_ENVIRONMENT ||
        process.env.NODE_ENV ||
        "production",
      isolationNote:
        "Reads only current Railway container process.env. Railway cannot read Vercel, Render, or Cloudflare Worker secrets."
    };
  }

  if (
    process.env.RENDER === "true" ||
    Boolean(process.env.RENDER_SERVICE_ID || process.env.RENDER_EXTERNAL_URL)
  ) {
    return {
      provider: "render",
      label: "Render Web Service (Node.js)",
      region: null,
      environment: process.env.NODE_ENV || "production",
      isolationNote:
        "Reads only current Render service process.env. Render cannot read Vercel, Railway, or Cloudflare Worker secrets."
    };
  }

  return {
    provider: "nodejs",
    label: "Native Node.js Runtime",
    region: null,
    environment: process.env.NODE_ENV || "development",
    isolationNote:
      "Reads only current local/container Node.js process.env. Remote Vercel, Railway, Render, and Cloudflare Worker variables remain isolated on their respective platforms."
  };
}

export function discoverRuntimeEnvironment(customTrackedVars = []) {
  const runtime = detectRuntimeProvider();
  const discoveredMap = new Map();
  let suppressedInternalCount = 0;

  const customTrackedMap = new Map(
    customTrackedVars.map((item) => [item.key, item])
  );

  // 1. Automatically discover all keys present in current runtime process.env (read-only)
  for (const key of Object.keys(process.env)) {
    const rawValue = process.env[key];
    if (isRestrictedInternalEnv(key, rawValue)) {
      suppressedInternalCount += 1;
      continue;
    }

    const catalog = CATALOG_MAP.get(key);
    const custom = customTrackedMap.get(key);
    const category = isSystemManagedKey(key) ? "system" : "user";
    const configured = typeof rawValue === "string" && rawValue.trim().length > 0;
    const isSecret = isSecretEnv(
      key,
      rawValue,
      custom?.isSecret ?? catalog?.isSecret
    );

    discoveredMap.set(key, {
      key,
      category,
      scope: custom?.scope || catalog?.scope || inferScope(key),
      isSecret,
      configured,
      status: configured ? "configured" : "missing",
      valuePreview: configured
        ? isSecret
          ? maskSecret(rawValue)
          : sanitizeSafePreview(rawValue)
        : "",
      discoveredAutomatically: true,
      managed: Boolean(custom),
      source: "process.env"
    });
  }

  // 2. Include expected provider-specific system keys (for configured/missing visibility)
  const providerExpected = PROVIDER_SYSTEM_EXPECTED_KEYS[runtime.provider] || [];
  for (const key of providerExpected) {
    if (discoveredMap.has(key) || isRestrictedInternalEnv(key)) continue;
    discoveredMap.set(key, {
      key,
      category: "system",
      scope: runtime.provider,
      isSecret: false,
      configured: false,
      status: "missing",
      valuePreview: "",
      discoveredAutomatically: false,
      managed: false,
      source: "provider-schema"
    });
  }

  // 3. Include known user-configured platform/integration keys from ENV_CATALOG
  for (const entry of ENV_CATALOG) {
    if (discoveredMap.has(entry.key) || isRestrictedInternalEnv(entry.key)) continue;
    discoveredMap.set(entry.key, {
      key: entry.key,
      category: "user",
      scope: entry.scope,
      isSecret: entry.isSecret,
      configured: false,
      status: "missing",
      valuePreview: "",
      discoveredAutomatically: false,
      managed: false,
      source: "catalog"
    });
  }

  // 4. Include admin-registered custom tracked variable names
  for (const custom of customTrackedVars) {
    if (discoveredMap.has(custom.key) || isRestrictedInternalEnv(custom.key)) continue;
    discoveredMap.set(custom.key, {
      key: custom.key,
      category: "user",
      scope: custom.scope || "custom",
      isSecret: Boolean(custom.isSecret),
      configured: false,
      status: "missing",
      valuePreview: "",
      discoveredAutomatically: false,
      managed: true,
      source: "admin-tracked"
    });
  }

  const all = Array.from(discoveredMap.values()).sort((a, b) =>
    a.key.localeCompare(b.key)
  );
  const systemVariables = all.filter((item) => item.category === "system");
  const userVariables = all.filter((item) => item.category === "user");

  return {
    runtime,
    suppressedInternalCount,
    summary: {
      totalVisible: all.length,
      systemCount: systemVariables.length,
      userCount: userVariables.length,
      configuredCount: all.filter((v) => v.configured).length,
      missingCount: all.filter((v) => !v.configured).length
    },
    systemVariables,
    userVariables
  };
}

export function getProcessEnvSummary() {
  return discoverRuntimeEnvironment().userVariables;
}
