/**
 * ==========================================
 * ASBILY CONTROLLER — CLOUDFLARE WORKERS
 * Central API Gateway & Routing Layer
 * Web Standards Runtime (Zero Node.js deps)
 * ==========================================
 */

const MAX_BODY_SIZE = 1024 * 1024; // 1 MB
const IDEMPOTENT_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);
const PROTECTED_V1_PREFIXES = [
  "/api/v1/account",
  "/api/v1/user",
  "/api/v1/users",
  "/api/v1/profile",
  "/api/v1/security",
  "/api/v1/notifications",
  "/api/v1/messages",
  "/api/v1/storage"
];

// Per-isolate rate limit buckets (supplemented by Cloudflare WAF / Rate Limiting rules in production)
const rateBuckets = new Map();

function jsonResponse(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
      ...extraHeaders
    }
  });
}

function errorResponse(status, code, message, extraHeaders = {}) {
  return jsonResponse(
    {
      success: false,
      error: { code, message }
    },
    status,
    extraHeaders
  );
}

function getCorsHeaders(request, env) {
  const origin = request.headers.get("Origin");
  const allowed = (env.ALLOWED_ORIGINS || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);

  const headers = {
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    Vary: "Origin"
  };

  if (origin) {
    if (allowed.includes("*") || allowed.includes(origin)) {
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

function checkRateLimit(ip, limit = 120, windowMs = 60000) {
  const now = Date.now();
  let entry = rateBuckets.get(ip);
  if (!entry || now >= entry.resetAt) {
    entry = { count: 0, resetAt: now + windowMs };
  }
  entry.count += 1;
  rateBuckets.set(ip, entry);

  if (rateBuckets.size > 4000) {
    for (const [k, v] of rateBuckets.entries()) {
      if (now >= v.resetAt) rateBuckets.delete(k);
    }
  }

  return {
    allowed: entry.count <= limit,
    limit,
    remaining: Math.max(0, limit - entry.count),
    resetAt: Math.ceil(entry.resetAt / 1000)
  };
}

function timingSafeEqualStrings(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  const enc = new TextEncoder();
  const aBytes = enc.encode(a);
  const bBytes = enc.encode(b);
  if (aBytes.length !== bBytes.length) return false;
  let diff = 0;
  for (let i = 0; i < aBytes.length; i++) {
    diff |= aBytes[i] ^ bBytes[i];
  }
  return diff === 0;
}

function base64UrlToUint8Array(str) {
  const padded = str.replace(/-/g, "+").replace(/_/g, "/");
  const padLen = (4 - (padded.length % 4)) % 4;
  const bin = atob(padded + "=".repeat(padLen));
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) {
    bytes[i] = bin.charCodeAt(i);
  }
  return bytes;
}

async function verifyJwtHS256(token, secret) {
  if (!token || !secret) return null;
  const parts = token.split(".");
  if (parts.length !== 3) return null;

  const [headerB64, payloadB64, sigB64] = parts;
  const enc = new TextEncoder();

  try {
    const key = await crypto.subtle.importKey(
      "raw",
      enc.encode(secret),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["verify"]
    );

    const verified = await crypto.subtle.verify(
      "HMAC",
      key,
      base64UrlToUint8Array(sigB64),
      enc.encode(`${headerB64}.${payloadB64}`)
    );

    if (!verified) return null;

    const payloadJson = new TextDecoder().decode(base64UrlToUint8Array(payloadB64));
    const claims = JSON.parse(payloadJson);
    const now = Math.floor(Date.now() / 1000);
    if (typeof claims.exp === "number" && claims.exp < now) {
      return null;
    }
    return claims;
  } catch {
    return null;
  }
}

function maskUrlConfigured(url) {
  if (!url) return null;
  try {
    const parsed = new URL(url);
    return `${parsed.protocol}//${parsed.host}`;
  } catch {
    return "invalid-url";
  }
}

async function loadGatewayConfig(env) {
  const baseProviders = {
    vercel: {
      id: "vercel",
      type: "vercel",
      url: (env.VERCEL_BACKEND_URL || "").replace(/\/+$/, ""),
      enabled: Boolean(env.VERCEL_BACKEND_URL),
      apiKey: env.VERCEL_API_KEY || "",
      apiSecret: env.VERCEL_API_SECRET || "",
      apiToken: env.VERCEL_API_TOKEN || ""
    },
    railway: {
      id: "railway",
      type: "railway",
      url: (env.RAILWAY_BACKEND_URL || "").replace(/\/+$/, ""),
      enabled: Boolean(env.RAILWAY_BACKEND_URL),
      apiKey: env.RAILWAY_API_KEY || "",
      apiSecret: env.RAILWAY_API_SECRET || "",
      apiToken: env.RAILWAY_API_TOKEN || ""
    },
    render: {
      id: "render",
      type: "render",
      url: (env.RENDER_BACKEND_URL || "").replace(/\/+$/, ""),
      enabled: Boolean(env.RENDER_BACKEND_URL),
      apiKey: env.RENDER_API_KEY || "",
      apiSecret: env.RENDER_API_SECRET || "",
      apiToken: env.RENDER_API_TOKEN || ""
    }
  };

  let kvRouting = null;
  if (env.CONTROLLER_CONFIG) {
    try {
      kvRouting = await env.CONTROLLER_CONFIG.get("routing", { type: "json" });
    } catch {
      kvRouting = null;
    }
  }

  return {
    providers: baseProviders,
    activeProvider: kvRouting?.activeProvider || (env.ACTIVE_PROVIDER || "vercel").toLowerCase(),
    defaultProvider: kvRouting?.defaultProvider || (env.DEFAULT_PROVIDER || "vercel").toLowerCase(),
    routes: Array.isArray(kvRouting?.routes) ? kvRouting.routes : []
  };
}

function selectProviders(config, pathname, requestedProvider) {
  const { providers, activeProvider, defaultProvider, routes } = config;

  const matchedRule = routes.find((r) => {
    if (!r.enabled || !r.pattern) return false;
    const prefix = r.pattern.replace(/\/?\*$/, "");
    return pathname === prefix || pathname.startsWith(`${prefix}/`);
  });

  let primaryKey = activeProvider;
  if (requestedProvider && providers[requestedProvider]?.enabled) {
    primaryKey = requestedProvider;
  } else if (matchedRule?.targetProvider && matchedRule.targetProvider !== "auto") {
    primaryKey = matchedRule.targetProvider;
  }

  let primary = providers[primaryKey];
  if (!primary || !primary.enabled || !primary.url) {
    primary = providers[defaultProvider];
  }
  if (!primary || !primary.enabled || !primary.url) {
    primary = Object.values(providers).find((p) => p.enabled && p.url) || null;
  }

  let fallback = null;
  const fallbackKey = matchedRule?.fallbackProvider || defaultProvider;
  if (
    fallbackKey &&
    providers[fallbackKey]?.enabled &&
    providers[fallbackKey]?.url &&
    providers[fallbackKey]?.id !== primary?.id
  ) {
    fallback = providers[fallbackKey];
  }

  return { primary, fallback, matchedRule };
}

async function forwardUpstream(request, provider, urlObj, requestId, timeoutMs = 8000, bodyBuffer = null) {
  const targetUrl = `${provider.url}${urlObj.pathname}${urlObj.search}`;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  const headers = new Headers();
  for (const [k, v] of request.headers.entries()) {
    const lower = k.toLowerCase();
    if (
      lower === "host" ||
      lower === "cf-connecting-ip" ||
      lower === "cf-ray" ||
      lower === "x-api-key" ||
      lower === "x-api-secret"
    ) {
      continue;
    }
    headers.set(k, v);
  }

  headers.set("X-Forwarded-By", "Asbily-Cloudflare-Gateway");
  headers.set("X-Request-Id", requestId);
  headers.set("X-Asbily-Target-Provider", provider.type);

  if (provider.apiKey) headers.set("X-API-Key", provider.apiKey);
  if (provider.apiSecret) headers.set("X-API-Secret", provider.apiSecret);
  if (provider.apiToken && !headers.has("Authorization")) {
    headers.set("Authorization", `Bearer ${provider.apiToken}`);
  }

  const method = request.method.toUpperCase();
  try {
    const upstreamRes = await fetch(targetUrl, {
      method,
      headers,
      body: method === "GET" || method === "HEAD" ? undefined : bodyBuffer,
      signal: controller.signal
    });
    return { ok: true, response: upstreamRes };
  } catch (err) {
    const isAbort = err.name === "AbortError";
    return {
      ok: false,
      status: isAbort ? 504 : 502,
      error: isAbort ? "Upstream request timed out" : err.message
    };
  } finally {
    clearTimeout(timer);
  }
}

export default {
  async fetch(request, env, ctx) {
    const requestId = crypto.randomUUID();
    const urlObj = new URL(request.url);
    const { pathname } = urlObj;
    const method = request.method.toUpperCase();
    const corsHeaders = getCorsHeaders(request, env);

    if (method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: {
          ...corsHeaders,
          "X-Request-Id": requestId
        }
      });
    }

    // Request Size Limit check
    const contentLength = Number(request.headers.get("Content-Length") || "0");
    if (Number.isFinite(contentLength) && contentLength > MAX_BODY_SIZE) {
      return errorResponse(413, "BODY_TOO_LARGE", "Request body exceeds 1 MB limit.", {
        ...corsHeaders,
        "X-Request-Id": requestId
      });
    }

    // Rate Limiting
    const clientIp = request.headers.get("CF-Connecting-IP") || "unknown";
    const rateLimit = Number(env.RATE_LIMIT_PER_MIN || "120");
    const rl = checkRateLimit(clientIp, rateLimit);
    const rlHeaders = {
      "X-RateLimit-Limit": String(rl.limit),
      "X-RateLimit-Remaining": String(rl.remaining),
      "X-RateLimit-Reset": String(rl.resetAt),
      "X-Request-Id": requestId,
      ...corsHeaders
    };

    if (!rl.allowed) {
      return errorResponse(429, "RATE_LIMITED", "Too many requests.", rlHeaders);
    }

    // Gateway Health Check
    if ((pathname === "/health" || pathname === "/gw/health") && method === "GET") {
      return jsonResponse(
        {
          success: true,
          service: "Asbily Cloudflare Workers Gateway",
          status: "online",
          timestamp: new Date().toISOString()
        },
        200,
        rlHeaders
      );
    }

    const config = await loadGatewayConfig(env);

    // Gateway Status (Masked configuration — never exposes secrets)
    if (pathname === "/gw/status" && method === "GET") {
      return jsonResponse(
        {
          success: true,
          gateway: "Asbily Cloudflare Workers",
          activeProvider: config.activeProvider,
          defaultProvider: config.defaultProvider,
          providers: Object.values(config.providers).map((p) => ({
            id: p.id,
            type: p.type,
            enabled: p.enabled,
            backendHost: maskUrlConfigured(p.url),
            hasApiKey: Boolean(p.apiKey),
            hasApiSecret: Boolean(p.apiSecret),
            hasApiToken: Boolean(p.apiToken)
          })),
          r2Configured: Boolean(env.ASBILY_STORAGE),
          kvConfigured: Boolean(env.CONTROLLER_CONFIG)
        },
        200,
        rlHeaders
      );
    }

    // Gateway Dynamic Routing Config Update (Protected by GATEWAY_ADMIN_TOKEN)
    if (pathname === "/gw/config" && method === "PUT") {
      const adminToken = request.headers.get("X-Gateway-Admin-Token") || "";
      if (!env.GATEWAY_ADMIN_TOKEN || !timingSafeEqualStrings(adminToken, env.GATEWAY_ADMIN_TOKEN)) {
        return errorResponse(401, "UNAUTHORIZED", "Invalid gateway admin token.", rlHeaders);
      }
      if (!env.CONTROLLER_CONFIG) {
        return errorResponse(
          501,
          "KV_NOT_BOUND",
          "CONTROLLER_CONFIG KV namespace is not bound.",
          rlHeaders
        );
      }
      const nextConfig = await request.json();
      await env.CONTROLLER_CONFIG.put("routing", JSON.stringify(nextConfig));
      return jsonResponse({ success: true, updated: true }, 200, rlHeaders);
    }

    // Validate API Versioning for /api/*
    if (pathname.startsWith("/api/") && !pathname.startsWith("/api/v1/") && pathname !== "/api/lemon-squeezy") {
      return errorResponse(
        400,
        "UNSUPPORTED_API_VERSION",
        "Use versioned API endpoints under /api/v1/*.",
        rlHeaders
      );
    }

    // Gateway-level Authentication Enforcement on protected /api/v1/* prefixes
    const requiresGatewayAuth = PROTECTED_V1_PREFIXES.some(
      (prefix) => pathname === prefix || pathname.startsWith(`${prefix}/`)
    );

    if (requiresGatewayAuth && env.GATEWAY_SIGNING_SECRET) {
      const authHeader = request.headers.get("Authorization") || "";
      const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7).trim() : "";
      const claims = await verifyJwtHS256(token, env.GATEWAY_SIGNING_SECRET);
      if (!claims) {
        return errorResponse(
          401,
          "UNAUTHORIZED",
          "Valid Bearer token required by API Gateway.",
          rlHeaders
        );
      }
    }

    // Buffer request body once if non-GET/HEAD to check exact byte length
    let bodyBuffer = null;
    if (method !== "GET" && method !== "HEAD") {
      bodyBuffer = await request.arrayBuffer();
      if (bodyBuffer.byteLength > MAX_BODY_SIZE) {
        return errorResponse(413, "BODY_TOO_LARGE", "Request body exceeds 1 MB limit.", rlHeaders);
      }
    }

    const requestedProvider = (request.headers.get("X-Asbily-Provider") || "").toLowerCase();
    const { primary, fallback, matchedRule } = selectProviders(
      config,
      pathname,
      requestedProvider
    );

    if (!primary) {
      return errorResponse(
        503,
        "NO_BACKEND_PROVIDER",
        "No backend provider URL is configured in Worker environment bindings.",
        rlHeaders
      );
    }

    const timeoutMs = Number(matchedRule?.timeoutMs || env.DEFAULT_TIMEOUT_MS || "8000");
    const primaryAttempt = await forwardUpstream(
      request,
      primary,
      urlObj,
      requestId,
      timeoutMs,
      bodyBuffer
    );

    const canSafeFallback =
      IDEMPOTENT_METHODS.has(method) &&
      Boolean(fallback) &&
      matchedRule?.allowSafeFallback !== false;

    let finalAttempt = primaryAttempt;
    let routedProvider = primary.type;
    let fallbackUsed = false;

    if ((!primaryAttempt.ok || primaryAttempt.response.status >= 500) && canSafeFallback) {
      const fallbackAttempt = await forwardUpstream(
        request,
        fallback,
        urlObj,
        requestId,
        timeoutMs,
        bodyBuffer
      );
      if (fallbackAttempt.ok) {
        finalAttempt = fallbackAttempt;
        routedProvider = fallback.type;
        fallbackUsed = true;
      }
    }

    if (!finalAttempt.ok) {
      return errorResponse(
        finalAttempt.status,
        "UPSTREAM_UNAVAILABLE",
        finalAttempt.error || "Backend provider error.",
        {
          ...rlHeaders,
          "X-Asbily-Routed-Provider": routedProvider
        }
      );
    }

    // Structured non-sensitive log
    console.log(
      JSON.stringify({
        requestId,
        method,
        pathname,
        provider: routedProvider,
        fallbackUsed,
        status: finalAttempt.response.status
      })
    );

    const respHeaders = new Headers(finalAttempt.response.headers);
    for (const [k, v] of Object.entries(rlHeaders)) {
      respHeaders.set(k, v);
    }
    respHeaders.set("X-Asbily-Routed-Provider", routedProvider);
    if (fallbackUsed) {
      respHeaders.set("X-Asbily-Fallback-Used", "true");
    }

    return new Response(finalAttempt.response.body, {
      status: finalAttempt.response.status,
      statusText: finalAttempt.response.statusText,
      headers: respHeaders
    });
  }
};
