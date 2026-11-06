import {
  createCheckout,
  handleWebhook
} from "./lemon-squeezy.js";

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8"
    }
  });
}

export default {
  async fetch(request) {
    try {
      const url = new URL(request.url);
      const path = url.pathname.replace(/\/+$/, "");
      const method = request.method.toUpperCase();

      // API Status
      if (
        method === "GET" &&
        path.endsWith("/api/lemon-squeezy")
      ) {
        return json({
          success: true,
          service: "Asbily Lemon Squeezy API",
          status: "online"
        });
      }

      // Checkout
      if (
        method === "POST" &&
        path.endsWith("/api/lemon-squeezy/checkout")
      ) {
        return await createCheckout(request);
      }

      // Webhook
      if (
        method === "POST" &&
        path.endsWith("/api/lemon-squeezy/webhook")
      ) {
        return await handleWebhook(request);
      }

      return json({
        success: false,
        message: "Endpoint not found"
      }, 404);

    } catch (error) {
      console.error("Lemon Squeezy Error:", error);

      return json({
        success: false,
        message: "Internal server error"
      }, 500);
    }
  }
};
