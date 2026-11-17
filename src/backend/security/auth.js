"use strict";

import { verifyToken } from "./crypto.js";
import { parseCookies, sendError } from "../utils/http.js";
import { stateStore } from "../store/stateStore.js";

export const ROLE_HIERARCHY = {
  viewer: 1,
  operator: 2,
  admin: 3,
  super_admin: 4
};

export function extractBearerToken(req) {
  const auth = req.headers.authorization;
  if (typeof auth === "string" && auth.startsWith("Bearer ")) {
    return auth.slice(7).trim();
  }
  const cookies = parseCookies(req);
  if (cookies.asbily_token) {
    return cookies.asbily_token;
  }
  return null;
}

export function authenticateRequest(req) {
  const token = extractBearerToken(req);
  if (!token) return null;

  const claims = verifyToken(token);
  if (!claims || !claims.sub) return null;

  const user = stateStore.state.users.find((u) => u.id === claims.sub);
  if (!user || user.status !== "active") {
    return null;
  }

  return stateStore.toPublicUser(user);
}

export function requireAuth(req, res) {
  const user = authenticateRequest(req);
  if (!user) {
    sendError(
      res,
      401,
      "Authentication required. Sign in to access this controller resource.",
      "UNAUTHORIZED"
    );
    return null;
  }
  return user;
}

export function requireRole(req, res, minRole = "admin") {
  const user = requireAuth(req, res);
  if (!user) return null;

  const userLevel = ROLE_HIERARCHY[user.role] || 0;
  const requiredLevel = ROLE_HIERARCHY[minRole] || 99;

  if (userLevel < requiredLevel) {
    sendError(
      res,
      403,
      `Insufficient permissions. Requires ${minRole} role or higher.`,
      "FORBIDDEN"
    );
    return null;
  }

  return user;
}
