"use strict";

import test from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import crypto from "node:crypto";

process.env.NODE_ENV = "test";

const { handleRequest } = await import("../src/backend/app.js");
const { stateStore } = await import("../src/backend/store/stateStore.js");
const { validateEvent } = await import("../api/lemon-squeezy/lemon-squeezy.js");
const workerModule = await import("../worker/src/index.js");
const worker = workerModule.default;

function startTempServer(handler) {
  return new Promise((resolve) => {
    const srv = createServer(handler);
    srv.listen(0, "127.0.0.1", () => {
      const addr = srv.address();
      resolve({
        server: srv,
        baseUrl: `http://127.0.0.1:${addr.port}`
      });
    });
  });
}

function stopServer(srv) {
  return new Promise((resolve) => srv.close(() => resolve()));
}

test("Asbily Controller Full Integration Suite", async (t) => {
  stateStore.resetForTests();
  const { server, baseUrl } = await startTempServer((req, res) => {
    handleRequest(req, res).catch((err) => {
      res.writeHead(500);
      res.end(err.message);
    });
  });

  t.after(async () => {
    await stopServer(server);
  });

  let adminToken = "";
  let viewerToken = "";

  await t.test("1. Frontend pages and static assets load with 200", async () => {
    for (const path of ["/", "/style.css", "/script.js", "/assets/logo.svg", "/dashboard", "/dashboard/dashboard.css", "/dashboard/dashboard.js"]) {
      const res = await fetch(`${baseUrl}${path}`);
      assert.equal(res.status, 200, `Expected 200 for ${path}`);
    }
  });

  await t.test("2. Health checks and API v1 service info respond online", async () => {
    const health = await fetch(`${baseUrl}/health`).then((r) => r.json());
    assert.equal(health.success, true);
    assert.equal(health.service, "Asbily Controller");

    const services = await fetch(`${baseUrl}/api/v1/services`).then((r) => r.json());
    assert.equal(services.success, true);
    assert.ok(Array.isArray(services.services));
  });

  await t.test("3. Unauthenticated admin mutations are blocked with 401", async () => {
    const res = await fetch(`${baseUrl}/api/controller/providers`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: "Unauthorized", type: "custom" })
    });
    assert.equal(res.status, 401);
  });

  await t.test("4. Admin bootstrap, duplicate bootstrap block (409), and RBAC enforcement (403)", async () => {
    const bootRes = await fetch(`${baseUrl}/api/v1/auth/bootstrap`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        name: "Test Admin",
        email: "admin@example.test",
        password: "TestPassword123!"
      })
    });
    assert.equal(bootRes.status, 201);
    const bootData = await bootRes.json();
    assert.ok(bootData.token);
    adminToken = bootData.token;

    const secondBoot = await fetch(`${baseUrl}/api/v1/auth/bootstrap`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        email: "other@example.test",
        password: "TestPassword123!"
      })
    });
    assert.equal(secondBoot.status, 409);

    // Create a viewer user
    const createViewer = await fetch(`${baseUrl}/api/v1/users`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${adminToken}`
      },
      body: JSON.stringify({
        name: "Read Only Viewer",
        email: "viewer@example.test",
        role: "viewer",
        password: "ViewerPassword123!"
      })
    });
    assert.equal(createViewer.status, 201);

    const viewerLogin = await fetch(`${baseUrl}/api/v1/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        email: "viewer@example.test",
        password: "ViewerPassword123!"
      })
    }).then((r) => r.json());
    viewerToken = viewerLogin.token;

    // Viewer must get 403 when attempting to add a provider
    const forbiddenRes = await fetch(`${baseUrl}/api/controller/providers`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${viewerToken}`
      },
      body: JSON.stringify({ name: "Blocked", type: "custom" })
    });
    assert.equal(forbiddenRes.status, 403);
  });

  await t.test("5. Environment secret protection masks secret values", async () => {
    const secretVal = "sk_test_super_sensitive_998877";
    const createEnv = await fetch(`${baseUrl}/api/controller/env`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${adminToken}`
      },
      body: JSON.stringify({
        scope: "vercel",
        key: "VERCEL_TEST_SECRET",
        value: secretVal,
        isSecret: true
      })
    });
    assert.equal(createEnv.status, 201);

    const listEnv = await fetch(`${baseUrl}/api/controller/env`).then((r) => r.json());
    const serialized = JSON.stringify(listEnv);
    assert.equal(serialized.includes(secretVal), false, "Raw secret must NEVER appear in API response");
    const found = listEnv.vaultVars.find((v) => v.key === "VERCEL_TEST_SECRET");
    assert.ok(found);
    assert.ok(found.valuePreview.includes("•"));
  });

  await t.test("6. Provider CRUD, live connection test, and idempotent-only fallback", async () => {
    // Spin up a real local mock upstream backend server
    let postCallCount = 0;
    const upstreamMock = await startTempServer((req, res) => {
      if (req.url === "/health") {
        res.writeHead(200, { "Content-Type": "application/json" });
        return res.end(JSON.stringify({ ok: true, service: "mock-upstream" }));
      }
      if (req.url === "/fail-endpoint") {
        if (req.method === "POST") postCallCount += 1;
        res.writeHead(502, { "Content-Type": "application/json" });
        return res.end(JSON.stringify({ error: "primary down" }));
      }
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ handledBy: "fallback-ok", method: req.method }));
    });

    const fallbackMock = await startTempServer((req, res) => {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ handledBy: "fallback-upstream", path: req.url }));
    });

    try {
      // Create healthy fallback provider (default)
      const fbRes = await fetch(`${baseUrl}/api/controller/providers`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${adminToken}`
        },
        body: JSON.stringify({
          name: "Mock Fallback Render",
          type: "render",
          backendUrl: fallbackMock.baseUrl,
          isDefault: true,
          enabled: true
        })
      }).then((r) => r.json());
      assert.equal(fbRes.success, true);

      // Create primary provider with secret API key
      const primRes = await fetch(`${baseUrl}/api/controller/providers`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${adminToken}`
        },
        body: JSON.stringify({
          name: "Mock Primary Railway",
          type: "railway",
          backendUrl: upstreamMock.baseUrl,
          apiKey: "rail_secret_key_123456",
          isActive: true,
          enabled: true
        })
      }).then((r) => r.json());
      assert.equal(primRes.success, true);
      assert.equal(JSON.stringify(primRes).includes("rail_secret_key_123456"), false);

      // Test live connection
      const testConn = await fetch(
        `${baseUrl}/api/controller/providers/${primRes.provider.id}/test`,
        {
          method: "POST",
          headers: { Authorization: `Bearer ${adminToken}` }
        }
      ).then((r) => r.json());
      assert.equal(testConn.testResult.ok, true);
      assert.equal(testConn.testResult.status, 200);

      // GET on /fail-endpoint should safely fall back to default provider
      const getFallback = await fetch(`${baseUrl}/api/controller/gateway/dispatch`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${adminToken}`
        },
        body: JSON.stringify({
          method: "GET",
          path: "/fail-endpoint",
          providerId: primRes.provider.id
        })
      }).then((r) => r.json());
      assert.equal(getFallback.dispatch.fallbackUsed, true);
      assert.equal(getFallback.dispatch.status, 200);

      // POST on /fail-endpoint MUST NOT auto-retry/fallback
      const postNoRetry = await fetch(`${baseUrl}/api/controller/gateway/dispatch`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${adminToken}`
        },
        body: JSON.stringify({
          method: "POST",
          path: "/fail-endpoint",
          providerId: primRes.provider.id,
          payload: { action: "charge" }
        })
      }).then((r) => r.json());
      assert.equal(postNoRetry.dispatch.fallbackUsed, false);
      assert.equal(postNoRetry.dispatch.status, 502);
      assert.equal(postCallCount, 1);
    } finally {
      await stopServer(upstreamMock.server);
      await stopServer(fallbackMock.server);
    }
  });

  await t.test("7. Request size limit rejects >1MB payloads with 413", async () => {
    const huge = "a".repeat(1024 * 1024 + 100);
    const res = await fetch(`${baseUrl}/api/v1/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: huge })
    });
    assert.equal(res.status, 413);
  });

  await t.test("8. Lemon Squeezy validation and webhook signature verification", async () => {
    process.env.LEMONSQUEEZY_STORE_ID = "12345";
    process.env.LEMONSQUEEZY_WEBHOOK_SECRET = "test_webhook_secret_abc";

    const validResult = validateEvent({
      meta: { event_name: "order_created" },
      data: { id: "ord_1", attributes: { store_id: 12345, variant_id: "999" } }
    });
    assert.equal(validResult.valid, true);

    const payload = JSON.stringify({
      meta: { event_name: "order_created" },
      data: { id: "ord_1", attributes: { store_id: 12345 } }
    });
    const sig = crypto
      .createHmac("sha256", "test_webhook_secret_abc")
      .update(payload)
      .digest("hex");

    const webhookRes = await fetch(`${baseUrl}/api/lemon-squeezy`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-signature": sig
      },
      body: payload
    });
    // Preserved handler returns 503 with verified: true
    assert.equal(webhookRes.status, 503);
    const body = await webhookRes.json();
    assert.equal(body.verified, true);
  });

  await t.test("9. Cloudflare Workers Gateway handles health, masked status, and versioning", async () => {
    const mockEnv = {
      ACTIVE_PROVIDER: "vercel",
      DEFAULT_PROVIDER: "vercel",
      VERCEL_BACKEND_URL: "https://example-backend.invalid",
      VERCEL_API_KEY: "cf_secret_key_should_not_leak"
    };

    const healthRes = await worker.fetch(new Request("https://gw.test/gw/health"), mockEnv, {});
    assert.equal(healthRes.status, 200);

    const statusRes = await worker.fetch(new Request("https://gw.test/gw/status"), mockEnv, {});
    assert.equal(statusRes.status, 200);
    const statusText = await statusRes.text();
    assert.equal(statusText.includes("cf_secret_key_should_not_leak"), false);

    const unversioned = await worker.fetch(new Request("https://gw.test/api/legacy/users"), mockEnv, {});
    assert.equal(unversioned.status, 400);
  });
});
