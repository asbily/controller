/**
 * ==========================================
 * ASBILY CONTROLLER
 * Native Node.js Backend Entry Point
 * ==========================================
 */

"use strict";

import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const PORT = Number(process.env.PORT) || 3000;

// ==========================================
// Response Helper
// ==========================================

function sendJSON(res, statusCode, data) {
  res.writeHead(statusCode, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff"
  });

  res.end(JSON.stringify(data));
}

// ==========================================
// Request Handler
// ==========================================

async function handleRequest(req, res) {
  const pathname = new URL(
    req.url,
    `http://${req.headers.host || "localhost"}`
  ).pathname;

  // Health Check
  if (pathname === "/health") {
    return sendJSON(res, 200, {
      success: true,
      service: "Asbily Controller",
      status: "online",
      timestamp: new Date().toISOString()
    });
  }

  // API Information
  if (pathname === "/api") {
    return sendJSON(res, 200, {
      name: "Asbily Controller API",
      version: "1.0.0",
      status: "online"
    });
  }

  // Homepage
  if (pathname === "/" && req.method === "GET") {
    try {
      const html = await readFile(
        join(__dirname, "index.html"),
        "utf8"
      );

      res.writeHead(200, {
        "Content-Type": "text/html; charset=utf-8",
        "X-Content-Type-Options": "nosniff"
      });

      return res.end(html);

    } catch {
      return sendJSON(res, 500, {
        success: false,
        error: "Homepage could not be loaded."
      });
    }
  }

  // Not Found
  return sendJSON(res, 404, {
    success: false,
    error: "Route not found."
  });
}

// ==========================================
// Native HTTP Server
// ==========================================

const server = createServer((req, res) => {
  handleRequest(req, res).catch((error) => {
    console.error("Controller Error:", error);

    if (!res.headersSent) {
      sendJSON(res, 500, {
        success: false,
        error: "Internal server error."
      });
    }
  });
});

// ==========================================
// Local Development Startup
// ==========================================

if (process.env.NODE_ENV !== "production") {
  server.listen(PORT, "0.0.0.0", () => {
    console.log(
      `Asbily Controller running at http://localhost:${PORT}`
    );
  });
}

export default server;
