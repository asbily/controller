/**
 * ==========================================
 * ASBILY CONTROLLER
 * Native Node.js HTTP Server Entry Point
 * Compatible with AI Studio, Railway, Render
 * ==========================================
 */

"use strict";

import { createServer } from "node:http";
import { handleRequest } from "./src/backend/app.js";

const PORT = Number(process.env.PORT) || 3000;
const HOST = process.env.HOST || "0.0.0.0";

const server = createServer((req, res) => {
  handleRequest(req, res).catch((error) => {
    console.error("Asbily Controller Server Error:", error.message);
    if (!res.headersSent) {
      res.writeHead(500, { "Content-Type": "application/json; charset=utf-8" });
      res.end(
        JSON.stringify({
          success: false,
          error: { code: "INTERNAL_ERROR", message: "Internal server error." }
        })
      );
    }
  });
});

if (!process.env.VERCEL && process.env.NODE_ENV !== "test") {
  server.listen(PORT, HOST, () => {
    console.log(`Asbily Controller running at http://${HOST}:${PORT}`);
  });
}

export { server, handleRequest };
export default server;
