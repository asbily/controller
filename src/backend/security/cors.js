"use strict";

export function getCorsHeaders(req) {
  const origin = req.headers.origin;
  const configured = (process.env.ALLOWED_ORIGINS || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);

  const headers = {
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
    "Vary": "Origin"
  };

  if (origin) {
    const requestHost = req.headers.host;
    let isSameHost = false;
    try {
      const originUrl = new URL(origin);
      isSameHost = Boolean(requestHost && originUrl.host === requestHost);
    } catch {
      isSameHost = false;
    }

    if (isSameHost || configured.includes("*") || configured.includes(origin)) {
      headers["Access-Control-Allow-Origin"] = origin;
      headers["Access-Control-Allow-Credentials"] = "true";
      headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, PATCH, DELETE, OPTIONS";
      headers["Access-Control-Allow-Headers"] =
        "Content-Type, Authorization, X-API-Key, X-Asbily-Provider, X-Request-Id";
      headers["Access-Control-Max-Age"] = "86400";
    }
  }

  return headers;
}
