"use strict";

const ALLOWED_EVENTS = new Set([
  "order_created",
  "order_refunded",
  "subscription_created",
  "subscription_updated",
  "subscription_cancelled",
  "subscription_resumed",
  "subscription_expired",
  "subscription_paused",
  "subscription_unpaused",
  "subscription_payment_failed",
  "subscription_payment_success",
  "subscription_payment_recovered",
  "subscription_payment_refunded",
  "subscription_plan_changed"
]);

const VARIANT_ENVIRONMENTS = {
  premium: "LEMONSQUEEZY_PREMIUM_VARIANT_ID",
  membership: "LEMONSQUEEZY_MEMBERSHIP_VARIANT_ID"
};

function getExpectedStoreId() {
  return String(process.env.LEMONSQUEEZY_STORE_ID || "");
}

function getProductType(variantId) {
  const normalizedId = String(variantId || "");

  for (const [product, envName] of Object.entries(VARIANT_ENVIRONMENTS)) {
    const expectedId = process.env[envName];

    if (expectedId && normalizedId === String(expectedId)) {
      return product;
    }
  }

  return null;
}

function validateEvent(payload) {
  if (!payload || typeof payload !== "object") {
    return {
      valid: false,
      reason: "Invalid payload."
    };
  }

  const eventName = payload.meta?.event_name;
  const data = payload.data;
  const attributes = data?.attributes;

  if (
    typeof eventName !== "string" ||
    !ALLOWED_EVENTS.has(eventName)
  ) {
    return {
      valid: false,
      reason: "Unsupported event."
    };
  }

  if (
    !data ||
    typeof data.id !== "string" ||
    !attributes ||
    typeof attributes !== "object"
  ) {
    return {
      valid: false,
      reason: "Invalid event data."
    };
  }

  const storeId = String(attributes.store_id || "");

  if (!getExpectedStoreId() || storeId !== getExpectedStoreId()) {
    return {
      valid: false,
      reason: "Store ID mismatch."
    };
  }

  const variantId = attributes.variant_id;
  const product = getProductType(variantId);

  return {
    valid: true,
    event: eventName,
    resourceId: data.id,
    storeId,
    variantId: String(variantId || ""),
    product
  };
}

function getEventSummary(payload) {
  const result = validateEvent(payload);

  if (!result.valid) {
    return result;
  }

  return {
    valid: true,
    event: result.event,
    resourceId: result.resourceId,
    product: result.product,
    storeId: result.storeId
  };
}

export {
  ALLOWED_EVENTS,
  getProductType,
  validateEvent,
  getEventSummary
};
