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
  if (str.length <= 8) {
    return "••••••••";
  }
  return `${"•".repeat(Math.min(12, str.length - 4))}${str.slice(-4)}`;
}

export const ENV_CATALOG = [
  { key: "ASBILY_ACCOUNT_URL", scope: "platform", isSecret: false },
  { key: "ASBILY_CONTROLLER_URL", scope: "platform", isSecret: false },
  { key: "ASBILY_MYACCOUNT_URL", scope: "platform", isSecret: false },
  { key: "CF_GATEWAY_URL", scope: "gateway", isSecret: false },
  { key: "GATEWAY_SIGNING_SECRET", scope: "gateway", isSecret: true },
  { key: "GATEWAY_ADMIN_TOKEN", scope: "gateway", isSecret: true },
  { key: "ACTIVE_PROVIDER", scope: "gateway", isSecret: false },
  { key: "DEFAULT_PROVIDER", scope: "gateway", isSecret: false },
  { key: "VERCEL_BACKEND_URL", scope: "vercel", isSecret: false },
  { key: "VERCEL_API_KEY", scope: "vercel", isSecret: true },
  { key: "VERCEL_API_SECRET", scope: "vercel", isSecret: true },
  { key: "VERCEL_API_TOKEN", scope: "vercel", isSecret: true },
  { key: "RAILWAY_BACKEND_URL", scope: "railway", isSecret: false },
  { key: "RAILWAY_API_KEY", scope: "railway", isSecret: true },
  { key: "RAILWAY_API_SECRET", scope: "railway", isSecret: true },
  { key: "RAILWAY_API_TOKEN", scope: "railway", isSecret: true },
  { key: "RENDER_BACKEND_URL", scope: "render", isSecret: false },
  { key: "RENDER_API_KEY", scope: "render", isSecret: true },
  { key: "RENDER_API_SECRET", scope: "render", isSecret: true },
  { key: "RENDER_API_TOKEN", scope: "render", isSecret: true },
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

export function getProcessEnvSummary() {
  return ENV_CATALOG.map((entry) => {
    const raw = process.env[entry.key] || "";
    const configured = raw.trim().length > 0;
    return {
      key: entry.key,
      scope: entry.scope,
      isSecret: entry.isSecret,
      configured,
      valuePreview: configured
        ? entry.isSecret
          ? maskSecret(raw)
          : raw
        : "",
      source: "environment"
    };
  });
}
