"use strict";

import crypto from "node:crypto";
import { getEncryptionKey, getSessionSecret } from "../config/env.js";

function base64UrlEncode(input) {
  return Buffer.from(input)
    .toString("base64")
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replaceAll("=", "");
}

function base64UrlDecode(input) {
  const padded = input.replaceAll("-", "+").replaceAll("_", "/");
  const padLen = (4 - (padded.length % 4)) % 4;
  return Buffer.from(padded + "=".repeat(padLen), "base64").toString("utf8");
}

export function encryptSecret(plaintext) {
  if (!plaintext) return "";
  const iv = crypto.randomBytes(12);
  const key = getEncryptionKey();
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const encrypted = Buffer.concat([
    cipher.update(String(plaintext), "utf8"),
    cipher.final()
  ]);
  const authTag = cipher.getAuthTag();
  return `${iv.toString("hex")}:${authTag.toString("hex")}:${encrypted.toString("hex")}`;
}

export function decryptSecret(payload) {
  if (!payload || typeof payload !== "string") return "";
  const parts = payload.split(":");
  if (parts.length !== 3) return "";
  try {
    const [ivHex, tagHex, dataHex] = parts;
    const iv = Buffer.from(ivHex, "hex");
    const authTag = Buffer.from(tagHex, "hex");
    const encrypted = Buffer.from(dataHex, "hex");
    const decipher = crypto.createDecipheriv("aes-256-gcm", getEncryptionKey(), iv);
    decipher.setAuthTag(authTag);
    return Buffer.concat([
      decipher.update(encrypted),
      decipher.final()
    ]).toString("utf8");
  } catch {
    return "";
  }
}

export function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");
  const derived = crypto.scryptSync(password, salt, 64).toString("hex");
  return `${salt}:${derived}`;
}

export function verifyPassword(password, storedHash) {
  if (!password || !storedHash || !storedHash.includes(":")) return false;
  const [salt, keyHex] = storedHash.split(":");
  const expectedBuffer = Buffer.from(keyHex, "hex");
  const derivedBuffer = crypto.scryptSync(password, salt, 64);
  if (expectedBuffer.length !== derivedBuffer.length) return false;
  return crypto.timingSafeEqual(expectedBuffer, derivedBuffer);
}

export function signToken(payload, expiresInSeconds = 60 * 60 * 8) {
  const now = Math.floor(Date.now() / 1000);
  const header = base64UrlEncode(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const body = base64UrlEncode(
    JSON.stringify({
      ...payload,
      iat: now,
      exp: now + expiresInSeconds
    })
  );
  const data = `${header}.${body}`;
  const sig = crypto
    .createHmac("sha256", getSessionSecret())
    .update(data)
    .digest("base64")
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replaceAll("=", "");
  return `${data}.${sig}`;
}

export function verifyToken(token) {
  if (!token || typeof token !== "string") return null;
  const parts = token.split(".");
  if (parts.length !== 3) return null;

  const [header, body, sig] = parts;
  const data = `${header}.${body}`;
  const expectedSig = crypto
    .createHmac("sha256", getSessionSecret())
    .update(data)
    .digest("base64")
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replaceAll("=", "");

  const a = Buffer.from(sig);
  const b = Buffer.from(expectedSig);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    return null;
  }

  try {
    const parsed = JSON.parse(base64UrlDecode(body));
    const now = Math.floor(Date.now() / 1000);
    if (typeof parsed.exp === "number" && parsed.exp < now) {
      return null;
    }
    return parsed;
  } catch {
    return null;
  }
}

export function createId(prefix = "id") {
  return `${prefix}_${crypto.randomUUID().replaceAll("-", "").slice(0, 12)}`;
}
