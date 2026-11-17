/**
 * ==========================================
 * ASBILY CONTROLLER
 * Vercel Serverless Adapter
 * ==========================================
 */

"use strict";

import { handleRequest } from "../src/backend/app.js";

export default async function handler(req, res) {
  return handleRequest(req, res);
}
