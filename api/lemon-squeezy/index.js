"use strict";

import crypto from "node:crypto";

const MAX_BODY_SIZE = 1024 * 1024;

function sendJSON(res, statusCode, data) {
  res.writeHead(statusCode, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff"
  });

  res.end(JSON.stringify(data));
}

async function readRawBody(req) {
  const chunks = [];
  let totalSize = 0;

  for await (const chunk of req) {
    totalSize += chunk.length;

    if (totalSize > MAX_BODY_SIZE) {
      throw new Error("BODY_TOO_LARGE");
    }

    chunks.push(chunk);
  }

  return Buffer.concat(chunks);
}

function verifySignature(rawBody, signature, secret) {
  if (
    typeof signature !== "string" ||
    !/^[a-f0-9]{64}$/i.test(signature)
  ) {
    return false;
  }

  const expected = crypto
    .createHmac("sha256", secret)
    .update(rawBody)
    .digest();

  const received = Buffer.from(signature, "hex");

  return (
    received.length === expected.length &&
    crypto.timingSafeEqual(expected, received)
  );
}

export default async function handler(req, res) {
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");

    return sendJSON(res, 405, {
      success: false,
      error: "Method not allowed."
    });
  }

  const secret = process.env.LEMONSQUEEZY_WEBHOOK_SECRET;

  if (!secret) {
    return sendJSON(res, 500, {
      success: false,
      error: "Webhook configuration is missing."
    });
  }

  let rawBody;

  try {
    rawBody = await readRawBody(req);
  } catch (error) {
    if (error.message === "BODY_TOO_LARGE") {
      return sendJSON(res, 413, {
        success: false,
        error: "Request body is too large."
      });
    }

    return sendJSON(res, 400, {
      success: false,
      error: "Could not read request body."
    });
  }

  const signature = req.headers["x-signature"];

  if (!verifySignature(rawBody, signature, secret)) {
    return sendJSON(res, 401, {
      success: false,
      error: "Invalid webhook signature."
    });
  }

  let payload;

  try {
    payload = JSON.parse(rawBody.toString("utf8"));
  } catch {
    return sendJSON(res, 400, {
      success: false,
      error: "Invalid JSON payload."
    });
  }

  const eventName = payload?.meta?.event_name;
  const resourceId = payload?.data?.id;

  if (
    typeof eventName !== "string" ||
    !payload?.data ||
    typeof payload.data !== "object"
  ) {
    return sendJSON(res, 400, {
      success: false,
      error: "Invalid webhook structure."
    });
  }

  // Temporary safety check:
  // Event storage and account processing are not implemented yet.
  // Do not activate or change any account here.

  console.log("Verified Lemon Squeezy webhook:", {
    event: eventName,
    resourceId: resourceId || null
  });

  return sendJSON(res, 503, {
    success: false,
    verified: true,
    message: "Webhook verified, but event processing is not configured yet."
  });
}
