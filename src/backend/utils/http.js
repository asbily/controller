"use strict";

export function sendJSON(res, statusCode, data, extraHeaders = {}) {
  res.writeHead(statusCode, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    ...extraHeaders
  });
  res.end(JSON.stringify(data));
}

export function sendError(res, statusCode, message, code = "ERROR", extraHeaders = {}) {
  return sendJSON(
    res,
    statusCode,
    {
      success: false,
      error: {
        code,
        message
      }
    },
    extraHeaders
  );
}

export function getClientIp(req) {
  const forwarded = req.headers["x-forwarded-for"];
  if (typeof forwarded === "string" && forwarded.trim()) {
    return forwarded.split(",")[0].trim();
  }
  const cfIp = req.headers["cf-connecting-ip"];
  if (typeof cfIp === "string" && cfIp.trim()) {
    return cfIp.trim();
  }
  return req.socket?.remoteAddress || "127.0.0.1";
}

export function parseCookies(req) {
  const cookieHeader = req.headers.cookie;
  const cookies = {};
  if (!cookieHeader || typeof cookieHeader !== "string") {
    return cookies;
  }

  for (const part of cookieHeader.split(";")) {
    const idx = part.indexOf("=");
    if (idx <= 0) continue;
    const key = part.slice(0, idx).trim();
    const val = part.slice(idx + 1).trim();
    try {
      cookies[key] = decodeURIComponent(val);
    } catch {
      cookies[key] = val;
    }
  }

  return cookies;
}
