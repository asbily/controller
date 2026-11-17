"use strict";

import { stateStore } from "../store/stateStore.js";
import { redactSensitive, sanitizeCustomHeaders } from "../security/validation.js";

const IDEMPOTENT_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

export function isIdempotentMethod(method) {
  return IDEMPOTENT_METHODS.has(String(method || "GET").toUpperCase());
}

export function matchRouteRule(pathname) {
  const routes = stateStore.state.routes.filter((r) => r.enabled);
  for (const rule of routes) {
    const prefix = rule.pattern.replace(/\/?\*$/, "");
    if (pathname === prefix || pathname.startsWith(`${prefix}/`)) {
      return rule;
    }
  }
  return null;
}

export function resolveProvidersForRequest({ requestedProviderId, routeRule }) {
  const providers = stateStore.state.providers.filter((p) => p.enabled);

  let primary = null;
  if (requestedProviderId && requestedProviderId !== "auto") {
    primary = providers.find(
      (p) => p.id === requestedProviderId || p.type === requestedProviderId
    );
  }

  if (!primary && routeRule?.targetProvider && routeRule.targetProvider !== "auto") {
    primary = providers.find(
      (p) => p.id === routeRule.targetProvider || p.type === routeRule.targetProvider
    );
  }

  if (!primary) {
    primary = stateStore.getActiveProvider() || stateStore.getDefaultProvider();
  }

  let fallback = null;
  if (routeRule?.fallbackProvider) {
    fallback = providers.find(
      (p) =>
        (p.id === routeRule.fallbackProvider || p.type === routeRule.fallbackProvider) &&
        p.id !== primary?.id
    );
  } else if (primary) {
    const def = stateStore.getDefaultProvider();
    if (def && def.id !== primary.id && def.backendUrl) {
      fallback = def;
    }
  }

  return { primary, fallback };
}

function buildUpstreamHeaders(provider, incomingHeaders = {}, requestId = "") {
  const creds = stateStore.getProviderCredentials(provider);
  const custom = sanitizeCustomHeaders(provider.customHeaders);

  const headers = {
    Accept: incomingHeaders.accept || "application/json",
    "X-Forwarded-By": "Asbily-Controller-Gateway",
    "X-Asbily-Provider": provider.type,
    ...(requestId ? { "X-Request-Id": requestId } : {}),
    ...custom
  };

  if (incomingHeaders["content-type"]) {
    headers["Content-Type"] = incomingHeaders["content-type"];
  }
  if (incomingHeaders.authorization) {
    headers.Authorization = incomingHeaders.authorization;
  } else if (creds.apiToken) {
    headers.Authorization = `Bearer ${creds.apiToken}`;
  }
  if (creds.apiKey) {
    headers["X-API-Key"] = creds.apiKey;
  }
  if (creds.apiSecret) {
    headers["X-API-Secret"] = creds.apiSecret;
  }

  return headers;
}

export async function testProviderConnection(provider) {
  const checkedAt = new Date().toISOString();
  if (!provider.backendUrl) {
    const result = {
      ok: false,
      status: 0,
      latencyMs: 0,
      checkedAt,
      targetUrl: "",
      error: "Backend URL is not configured.",
      responsePreview: null
    };
    provider.lastTest = result;
    await stateStore.persist();
    return result;
  }

  const healthPath = provider.healthPath?.startsWith("/")
    ? provider.healthPath
    : `/${provider.healthPath || "health"}`;
  const targetUrl = `${provider.backendUrl}${healthPath}`;
  const timeoutMs = Math.min(Math.max(Number(provider.timeoutMs) || 8000, 1000), 30000);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  const started = performance.now();

  try {
    const upstreamRes = await fetch(targetUrl, {
      method: "GET",
      headers: buildUpstreamHeaders(provider, { accept: "application/json" }),
      signal: controller.signal
    });

    const latencyMs = Math.round(performance.now() - started);
    const contentType = upstreamRes.headers.get("content-type") || "";
    const text = await upstreamRes.text();
    let preview = text.slice(0, 600);

    if (contentType.includes("application/json")) {
      try {
        preview = redactSensitive(JSON.parse(text));
      } catch {
        preview = text.slice(0, 600);
      }
    }

    const result = {
      ok: upstreamRes.ok,
      status: upstreamRes.status,
      latencyMs,
      checkedAt,
      targetUrl,
      error: upstreamRes.ok ? null : `Upstream responded with HTTP ${upstreamRes.status}`,
      responsePreview: preview
    };
    provider.lastTest = result;
    await stateStore.persist();
    return result;
  } catch (err) {
    const latencyMs = Math.round(performance.now() - started);
    const isAbort = err.name === "AbortError";
    const result = {
      ok: false,
      status: isAbort ? 504 : 502,
      latencyMs,
      checkedAt,
      targetUrl,
      error: isAbort
        ? `Connection timed out after ${timeoutMs}ms.`
        : `Connection failed: ${err.message}`,
      responsePreview: null
    };
    provider.lastTest = result;
    await stateStore.persist();
    return result;
  } finally {
    clearTimeout(timer);
  }
}

export async function forwardToProvider({
  provider,
  fallbackProvider = null,
  method = "GET",
  pathname,
  search = "",
  headers = {},
  body = undefined,
  timeoutMs = 8000,
  allowSafeFallback = true,
  requestId = ""
}) {
  const upperMethod = String(method).toUpperCase();
  const canFallback =
    Boolean(fallbackProvider?.backendUrl) &&
    Boolean(allowSafeFallback) &&
    stateStore.state.settings.safeIdempotentFallbackOnly !== false &&
    isIdempotentMethod(upperMethod);

  async function attempt(targetProvider) {
    if (!targetProvider?.backendUrl) {
      return {
        ok: false,
        status: 503,
        latencyMs: 0,
        provider: targetProvider?.type || "unconfigured",
        error: "Selected backend provider does not have a configured Backend URL.",
        headers: {},
        body: {
          success: false,
          error: {
            code: "PROVIDER_UNCONFIGURED",
            message: "Selected backend provider URL is not configured."
          }
        }
      };
    }

    const targetUrl = `${targetProvider.backendUrl}${pathname}${search}`;
    const effectiveTimeout = Math.min(
      Math.max(Number(targetProvider.timeoutMs || timeoutMs) || 8000, 1000),
      30000
    );
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), effectiveTimeout);
    const started = performance.now();

    try {
      const upstreamRes = await fetch(targetUrl, {
        method: upperMethod,
        headers: buildUpstreamHeaders(targetProvider, headers, requestId),
        body: upperMethod === "GET" || upperMethod === "HEAD" ? undefined : body,
        signal: controller.signal
      });

      const latencyMs = Math.round(performance.now() - started);
      const rawText = await upstreamRes.text();
      let parsedBody = rawText;
      const contentType = upstreamRes.headers.get("content-type") || "";
      if (contentType.includes("application/json")) {
        try {
          parsedBody = JSON.parse(rawText);
        } catch {
          parsedBody = rawText;
        }
      }

      return {
        ok: upstreamRes.ok,
        status: upstreamRes.status,
        latencyMs,
        provider: targetProvider.type,
        providerId: targetProvider.id,
        contentType,
        body: parsedBody,
        headers: {
          "X-Asbily-Routed-Provider": targetProvider.type
        }
      };
    } catch (err) {
      const latencyMs = Math.round(performance.now() - started);
      const isAbort = err.name === "AbortError";
      return {
        ok: false,
        status: isAbort ? 504 : 502,
        latencyMs,
        provider: targetProvider.type,
        providerId: targetProvider.id,
        error: isAbort ? "Upstream gateway timeout" : err.message,
        headers: {},
        body: {
          success: false,
          error: {
            code: isAbort ? "GATEWAY_TIMEOUT" : "BAD_GATEWAY",
            message: isAbort
              ? `Upstream provider timed out after ${effectiveTimeout}ms.`
              : `Upstream provider connection failed: ${err.message}`
          }
        }
      };
    } finally {
      clearTimeout(timer);
    }
  }

  const primaryResult = await attempt(provider);
  if (primaryResult.status < 500 || !canFallback) {
    return {
      ...primaryResult,
      fallbackUsed: false,
      retryBlockedReason:
        primaryResult.status >= 500 && !isIdempotentMethod(upperMethod)
          ? "Non-idempotent request not retried automatically."
          : null
    };
  }

  const fallbackResult = await attempt(fallbackProvider);
  return {
    ...fallbackResult,
    fallbackUsed: true,
    primaryFailedStatus: primaryResult.status
  };
}
