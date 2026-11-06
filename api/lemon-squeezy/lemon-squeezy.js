import crypto from "node:crypto";

// JSON Response
function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8"
    }
  });
}

// Create Lemon Squeezy Checkout
export async function createCheckout(request) {
  try {
    const apiKey = process.env.LEMONSQUEEZY_API_KEY;
    const storeId = process.env.LEMONSQUEEZY_STORE_ID;

    if (!apiKey || !storeId) {
      return json({
        success: false,
        message: "Payment API configuration is incomplete"
      }, 503);
    }

    let body;

    try {
      body = await request.json();
    } catch {
      return json({
        success: false,
        message: "Invalid JSON request"
      }, 400);
    }

    const plans = {
      premium: process.env.LEMONSQUEEZY_PREMIUM_VARIANT_ID,
      membership:
        process.env.LEMONSQUEEZY_MEMBERSHIP_VARIANT_ID
    };

    const plan = body.plan;

    if (!Object.hasOwn(plans, plan)) {
      return json({
        success: false,
        message: "Invalid product selection"
      }, 400);
    }

    const variantId = plans[plan];

    if (!variantId || !/^\d+$/.test(variantId)) {
      return json({
        success: false,
        message: "Product Variant ID is not configured"
      }, 503);
    }

    const apiUrl =
      process.env.LEMONSQUEEZY_API_URL ||
      "https://api.lemonsqueezy.com/v1";

    const response = await fetch(
      `${apiUrl}/checkouts`,
      {
        method: "POST",
        headers: {
          "Accept": "application/vnd.api+json",
          "Content-Type": "application/vnd.api+json",
          "Authorization": `Bearer ${apiKey}`
        },
        body: JSON.stringify({
          data: {
            type: "checkouts",
            attributes: {
              checkout_options: {
                embed: true
              }
            },
            relationships: {
              store: {
                data: {
                  type: "stores",
                  id: storeId
                }
              },
              variant: {
                data: {
                  type: "variants",
                  id: variantId
                }
              }
            }
          }
        })
      }
    );

    const result = await response.json();

    if (!response.ok) {
      console.error(
        "Lemon Squeezy Checkout Error:",
        response.status
      );

      return json({
        success: false,
        message: "Unable to create checkout"
      }, 502);
    }

    const checkoutUrl = result?.data?.attributes?.url;

    if (!checkoutUrl) {
      return json({
        success: false,
        message: "Checkout URL was not returned"
      }, 502);
    }

    return json({
      success: true,
      plan,
      checkout_url: checkoutUrl
    });

  } catch (error) {
    console.error("Checkout Error:", error);

    return json({
      success: false,
      message: "Checkout service error"
    }, 500);
  }
}

// Verify Webhook Signature
function verifySignature(rawBody, signature, secret) {
  if (!signature || !secret) {
    return false;
  }

  const digest = crypto
    .createHmac("sha256", secret)
    .update(rawBody)
    .digest("hex");

  const expected = Buffer.from(digest, "hex");
  const received = Buffer.from(signature, "hex");

  if (
    expected.length !== received.length ||
    received.length === 0
  ) {
    return false;
  }

  return crypto.timingSafeEqual(expected, received);
}

// Handle Lemon Squeezy Webhook
export async function handleWebhook(request) {
  try {
    const secret = process.env.LEMONSQUEEZY_WEBHOOK_SECRET;

    if (!secret) {
      return json({
        success: false,
        message: "Webhook secret is not configured"
      }, 503);
    }

    // Read original request body
    const rawBody = await request.text();

    const signature = request.headers.get("x-signature");

    if (!verifySignature(rawBody, signature, secret)) {
      return json({
        success: false,
        message: "Invalid webhook signature"
      }, 401);
    }

    let event;

    try {
      event = JSON.parse(rawBody);
    } catch {
      return json({
        success: false,
        message: "Invalid webhook payload"
      }, 400);
    }

    const eventName =
      request.headers.get("x-event-name") ||
      event?.meta?.event_name;

    const supportedEvents = [
      "order_created",
      "order_refunded"
    ];

    if (!supportedEvents.includes(eventName)) {
      return json({
        success: true,
        message: "Webhook event received",
        processed: false
      });
    }

    // Database processing will be added
    // after the Asbily account database is connected.

    console.log("Verified Lemon Squeezy Event:", eventName);

    return json({
      success: true,
      message: "Webhook signature verified",
      event: eventName,
      processed: false
    });

  } catch (error) {
    console.error("Webhook Error:", error);

    return json({
      success: false,
      message: "Webhook processing error"
    }, 500);
  }
}

// Prevent direct access to this helper module
export default {
  async fetch() {
    return json({
      success: false,
      message: "Not found"
    }, 404);
  }
};
