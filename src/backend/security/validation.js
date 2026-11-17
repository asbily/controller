"use strict";

export const MAX_BODY_SIZE = 1024 * 1024; // 1 MB

const SENSITIVE_KEY_PATTERN = /(secret|password|token|api[_-]?key|authorization|cookie|private|credential)/i;
const FORBIDDEN_HEADER_NAMES = new Set([
  "host",
  "connection",
  "content-length",
  "transfer-encoding",
  "upgrade",
  "keep-alive"
]);

export async function readRawBody(req, maxBytes = MAX_BODY_SIZE) {
  const declaredLength = Number(req.headers["content-length"]);
  if (Number.isFinite(declaredLength) && declaredLength > maxBytes) {
    const err = new Error("Request body exceeds maximum allowed size.");
    err.code = "BODY_TOO_LARGE";
    err.statusCode = 413;
    throw err;
  }

  const chunks = [];
  let total = 0;

  for await (const chunk of req) {
    total += chunk.length;
    if (total > maxBytes) {
      const err = new Error("Request body exceeds maximum allowed size.");
      err.code = "BODY_TOO_LARGE";
      err.statusCode = 413;
      throw err;
    }
    chunks.push(chunk);
  }

  return Buffer.concat(chunks);
}

export async function readJsonBody(req, maxBytes = MAX_BODY_SIZE) {
  const raw = await readRawBody(req, maxBytes);
  if (raw.length === 0) return {};

  try {
    const parsed = JSON.parse(raw.toString("utf8"));
    if (parsed === null || typeof parsed !== "object") {
      const err = new Error("Request body must be a JSON object or array.");
      err.code = "INVALID_JSON";
      err.statusCode = 400;
      throw err;
    }
    return parsed;
  } catch (err) {
    if (err.statusCode) throw err;
    const jsonErr = new Error("Malformed JSON request body.");
    jsonErr.code = "INVALID_JSON";
    jsonErr.statusCode = 400;
    throw jsonErr;
  }
}

export function validateBackendUrl(rawUrl) {
  if (typeof rawUrl !== "string" || !rawUrl.trim()) {
    return { valid: false, error: "Backend URL is required." };
  }

  const trimmed = rawUrl.trim();
  let parsed;
  try {
    parsed = new URL(trimmed);
  } catch {
    return { valid: false, error: "Invalid URL format." };
  }

  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
    return { valid: false, error: "Only HTTP and HTTPS protocols are permitted." };
  }

  if (parsed.username || parsed.password) {
    return { valid: false, error: "Embedded credentials in URLs are not allowed." };
  }

  return {
    valid: true,
    normalized: parsed.toString().replace(/\/+$/, "")
  };
}

export function sanitizeCustomHeaders(headers) {
  if (!headers || typeof headers !== "object" || Array.isArray(headers)) {
    return {};
  }

  const cleaned = {};
  for (const [k, v] of Object.entries(headers)) {
    const key = String(k).trim();
    if (!key || !/^[a-zA-Z0-9-]+$/.test(key)) continue;
    if (FORBIDDEN_HEADER_NAMES.has(key.toLowerCase())) continue;
    cleaned[key] = String(v ?? "").slice(0, 1024);
  }
  return cleaned;
}

export function redactSensitive(value) {
  if (Array.isArray(value)) {
    return value.map(redactSensitive);
  }
  if (value && typeof value === "object") {
    const output = {};
    for (const [key, val] of Object.entries(value)) {
      if (SENSITIVE_KEY_PATTERN.test(key)) {
        output[key] = "[REDACTED]";
      } else {
        output[key] = redactSensitive(val);
      }
    }
    return output;
  }
  return value;
}

export function isValidEnvKey(key) {
  return typeof key === "string" && /^[A-Z][A-Z0-9_]{1,63}$/.test(key);
}
