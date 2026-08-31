import express from "express";
import crypto from "node:crypto";
import { Resend } from "resend";
import "dotenv/config";

const app = express();
app.use(express.json({ limit: "1mb" }));
const notificationState = new Map();
const deliveredOrderIds = new Set();

const PORT = Number(process.env.PORT || 3000);
const SOFTSTORE_API_BASE =
  process.env.SOFTSTORE_API_BASE || "https://api.softstore.app/api/v1";
const DIGISELLER_API_BASE =
  process.env.DIGISELLER_API_BASE || "https://api.digiseller.com/api";

let softstoreJwt = null;
let softstoreJwtExpiresAt = 0;
let digisellerToken = null;
let digisellerTokenExpiresAt = 0;

function required(name) {
  const value = process.env[name];
  if (!value) throw new Error(`Missing environment variable: ${name}`);
  return value;
}

function sanitizeForLogs(value) {
  if (Array.isArray(value)) return value.map(sanitizeForLogs);

  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([key, item]) => [
        key,
        /authorization|api[_-]?key|token|secret|password/i.test(key)
          ? "[REDACTED]"
          : sanitizeForLogs(item)
      ])
    );
  }

  if (typeof value === "string") {
    return value.replace(
      /(authorization|api[_-]?key|token|secret|password)\s*[:=]\s*[^,\s}&]+/gi,
      "$1=[REDACTED]"
    );
  }

  return value;
}

function sanitizeUrlForLogs(value) {
  try {
    const url = new URL(String(value));

    for (const key of [...url.searchParams.keys()]) {
      if (/authorization|api[_-]?key|token|secret|password/i.test(key)) {
        url.searchParams.set(key, "[REDACTED]");
      }
    }

    return url.toString();
  } catch {
    return String(value);
  }
}

async function jsonFetch(url, options = {}) {
  const response = await fetch(url, options);
  const text = await response.text();
  let data;
  try {
    data = text ? JSON.parse(text) : {};
  } catch {
    data = { raw: text };
  }

  if (!response.ok) {
    const safeUrl = sanitizeUrlForLogs(url);
    const safeData = sanitizeForLogs(data);

    const error = new Error(
      `HTTP ${response.status} from ${safeUrl}: ${JSON.stringify(safeData)}`
    );
    error.status = response.status;
    error.data = safeData;
    throw error;
  }
  return data;
}

async function getSoftStoreJwt() {
  if (softstoreJwt && Date.now() < softstoreJwtExpiresAt - 30_000) {
    return softstoreJwt;
  }

  const apiKey = required("SOFTSTORE_API_KEY");
  const data = await jsonFetch(
    `${SOFTSTORE_API_BASE}/auth/api-key/create`,
    {
      method: "POST",
      headers: {
        "X-API-KEY": apiKey,
        "Content-Type": "application/json",
        Accept: "application/json"
      },
      body: "{}"
    }
  );

  const token = data.access_token ?? data.data?.access_token;
  if (!token) throw new Error(`SoftStore JWT missing: ${JSON.stringify(data)}`);

  softstoreJwt = token;
  const expiresIn = Number(data.expires_in ?? data.data?.expires_in ?? 3600);
  softstoreJwtExpiresAt = Date.now() + expiresIn * 1000;
  return softstoreJwt;
}

async function softstoreRequest(path, options = {}) {
  const jwt = await getSoftStoreJwt();
  return jsonFetch(`${SOFTSTORE_API_BASE}${path}`, {
    ...options,
    headers: {
      Accept: "application/json",
      ...(options.body ? { "Content-Type": "application/json" } : {}),
      ...(options.headers || {}),
      Authorization: `Bearer ${jwt}`
    }
  });
}

async function getDigisellerToken() {
  if (digisellerToken && Date.now() < digisellerTokenExpiresAt - 60_000) {
    return digisellerToken;
  }

  const sellerId = required("DIGISELLER_SELLER_ID");
  const apiKey = required("DIGISELLER_API_KEY");
  const timestamp = Math.floor(Date.now() / 1000);
  const sign = crypto
    .createHash("sha256")
    .update(`${apiKey}${timestamp}`)
    .digest("hex");

  const data = await jsonFetch(`${DIGISELLER_API_BASE}/apilogin`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json"
    },
    body: JSON.stringify({
      seller_id: Number(sellerId),
      timestamp,
      sign
    })
  });

  if (Number(data.retval) !== 0 || !data.token) {
    throw new Error(`Digiseller login failed: ${JSON.stringify(data)}`);
  }

  digisellerToken = data.token;
  digisellerTokenExpiresAt = Date.now() + 115 * 60 * 1000;
  return digisellerToken;
}

async function digisellerRequest(path, options = {}, includeToken = true) {
  const token = includeToken ? await getDigisellerToken() : null;
  const separator = path.includes("?") ? "&" : "?";
  const url = includeToken
    ? `${DIGISELLER_API_BASE}${path}${separator}token=${encodeURIComponent(token)}`
    : `${DIGISELLER_API_BASE}${path}`;

  return jsonFetch(url, {
    ...options,
    headers: {
      Accept: "application/json",
      ...(options.headers || {})
    }
  });
}

function verifySoftStoreWebhook(payload) {
  const apiKey = required("SOFTSTORE_API_KEY");
  const expected = crypto
    .createHash("sha1")
    .update(
      crypto.createHash("sha1").update(apiKey).digest("hex") +
      String(payload.id_order ?? "")
    )
    .digest("hex");

  const expectedBuffer = Buffer.from(expected);
  const suppliedBuffer = Buffer.from(String(payload.signature ?? ""));

  if (expectedBuffer.length !== suppliedBuffer.length) {
    return false;
  }

  return crypto.timingSafeEqual(expectedBuffer, suppliedBuffer);
}

function adminGuard(req, res, next) {
  const expected = required("ADMIN_SECRET");
  const supplied = req.get("X-ADMIN-SECRET");
  if (!supplied || supplied !== expected) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  next();
}

function getOrderSummary(order, payload) {
  const source = order && typeof order === "object" ? order : {};
  const idOrder = payload?.id_order ?? source.id_order ?? "N/A";
  const productId = payload?.id_product ?? source.id_product ?? source.product_id ?? "N/A";
  const quantity = source.quantity ?? source.qty ?? source.count ?? source.items?.quantity ?? "N/A";
  const amount = source.amount ?? source.total_amount ?? source.total ?? source.price ?? "N/A";
  const currency = source.currency ?? source.currency_code ?? "N/A";
  const paymentStatus = payload?.payment_status ?? source.payment_status ?? "PAID";

  return {
    idOrder,
    productId,
    quantity,
    amount,
    currency,
    paymentStatus
  };
}

function getTelegramOrderSummary(order) {
  const source = order && typeof order === "object" ? order : {};
  const details = source.order && typeof source.order === "object" ? source.order : source;
  const product = details.product && typeof details.product === "object" ? details.product : {};

  return {
    productName: details.product_name ?? details.name ?? details.title ?? product.name ?? "N/A",
    quantity: details.quantity ?? details.qty ?? details.count ?? details.items?.quantity ?? "N/A",
    amount: details.amount ?? details.total_amount ?? details.total ?? details.price ?? "N/A",
    currency: details.currency ?? details.currency_code ?? "N/A",
    idOrder: details.id_order ?? details.order_id ?? "N/A",
    productId: details.id_product ?? details.product_id ?? product.id ?? "N/A"
  };
}

function getNotificationState(orderId) {
  const key = String(orderId || "");

  if (!key || key === "N/A") {
    return {
      key: null,
      telegram: false,
      email: false
    };
  }

  const saved =
    notificationState.get(key) || {};

  return {
    key,
    telegram: saved.telegram === true,
    email: saved.email === true
  };
}

function saveNotificationState(state) {
  if (!state.key) return;

  notificationState.set(
    state.key,
    {
      telegram: state.telegram === true,
      email: state.email === true
    }
  );
}

async function sendOrderNotifications(order, payload) {
  const orderId =
    payload?.id_order ?? order?.id_order ?? "N/A";

  const state =
    getNotificationState(orderId);

  if (state.telegram && state.email) {
    console.warn(
      `[notifications] Duplicate notification suppressed for order ID ${orderId}.`
    );

    return state;
  }

  if (!state.telegram) {
    state.telegram =
      await sendTelegramOrderNotification(
        order,
        payload
      );
  }

  if (!state.email) {
    state.email =
      await sendGmailOrderNotification(
        order,
        payload
      );
  }

  saveNotificationState(state);
  return state;
}

async function sendTelegramOrderNotification(order, payload, test = false) {
  const token = process.env.TELEGRAM_BOT_TOKEN;
  const chatId = process.env.TELEGRAM_CHAT_ID;

  if (!token || !chatId) {
    console.warn("[telegram] Telegram notification is not configured; skipping.");
    return false;
  }

  const summary = getTelegramOrderSummary(order);
  const lines = [
    ...(test ? ["TEST NOTIFICATION - NOT A REAL ORDER", ""] : []),
    "🛒 NEW SOFTSTORE ORDER",
    "",
    `Product: ${summary.productName}`,
    `Quantity: ${summary.quantity}`,
    `Amount: ${summary.amount}`,
    `Currency: ${summary.currency}`,
    `Order ID: ${summary.idOrder}`,
    `Product ID: ${summary.productId}`,
    "Payment Status: PAID"
  ];

  const extraDetails = [];
  if (order?.status) extraDetails.push(`Status: ${order.status}`);
  if (order?.email) extraDetails.push(`Email: ${order.email}`);
  if (order?.customer_name) extraDetails.push(`Customer: ${order.customer_name}`);
  if (order?.created_at) extraDetails.push(`Created: ${order.created_at}`);

  if (extraDetails.length) lines.push("", ...extraDetails);

  try {
    const response = await fetch(`https://api.telegram.org/bot${token}/sendMessage`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        chat_id: chatId,
        text: lines.join("\n"),
        disable_web_page_preview: true
      })
    });

    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(data?.description || `Telegram API failed with status ${response.status}`);
    }

    return true;
  } catch (error) {
    console.error("[telegram] Failed to send notification safely.");
    console.error(error.message);
    return false;
  }
}

async function sendGmailOrderNotification(order, payload, test = false) {
  const resendApiKey = process.env.RESEND_API_KEY;
  const resendFromEmail = process.env.RESEND_FROM_EMAIL;
  const notificationEmail = process.env.NOTIFICATION_EMAIL;

  if (!resendApiKey || !resendFromEmail || !notificationEmail) {
    console.warn("[email] Resend notification is not configured; skipping.");
    return false;
  }

  const summary = getOrderSummary(order, payload);
  const subject = test
    ? "TEST NOTIFICATION - NOT A REAL ORDER"
    : `🛒 New SoftStore Order - ${summary.idOrder}`;
  const lines = [
    ...(test ? ["TEST NOTIFICATION - NOT A REAL ORDER", ""] : []),
    "New SoftStore order received.",
    "",
    `Order ID: ${summary.idOrder}`,
    `Product ID: ${summary.productId}`,
    `Quantity: ${summary.quantity}`,
    `Amount: ${summary.amount}`,
    `Currency: ${summary.currency}`,
    "Payment Status: PAID"
  ];

  if (order?.status) lines.push(`Status: ${order.status}`);
  if (order?.created_at) lines.push(`Created: ${order.created_at}`);

  try {
    const resend = new Resend(resendApiKey);
    const { error } = await resend.emails.send({
      from: resendFromEmail,
      to: notificationEmail,
      subject,
      text: lines.join("\n")
    });

    if (error) {
      throw new Error(error.message || "Resend email API request failed");
    }

    return true;
  } catch (error) {
    console.error("[email] Resend notification failed safely.");
    console.error(error.message || "Resend email API request failed");
    return false;
  }
}

app.get("/health", (_req, res) => {
  res.json({ ok: true, service: "softstore-digiseller-integration" });
});

app.get("/", (_req, res) => {
  res.status(200).json({
    status: "ok",
    service: "SoftStore-Digiseller integration"
  });
});

app.post("/admin/test-notifications", adminGuard, async (_req, res) => {
  const fakePayload = {
    id_order: "TEST-ORDER-123",
    id_product: "TEST-123",
    payment_status: "paid"
  };
  const fakeOrder = {
    id_order: "TEST-ORDER-123",
    id_product: "TEST-123",
    quantity: 1,
    payment_status: "paid",
    name: "TEST PRODUCT"
  };

  const [telegram, gmail] = await Promise.all([
    sendTelegramOrderNotification(fakeOrder, fakePayload, true),
    sendGmailOrderNotification(fakeOrder, fakePayload, true)
  ]);

  res.json({
    ok: telegram && gmail,
    telegram,
    gmail
  });
});

/**
 * Check Digiseller authentication and return the seller's visible catalog.
 */
app.get("/admin/digiseller/products", adminGuard, async (_req, res) => {
  try {
    const sellerId = required("DIGISELLER_SELLER_ID");
    const data = await digisellerRequest(`/categories?seller_id=${encodeURIComponent(sellerId)}`);
    res.json(data);
  } catch (error) {
    console.error(error);
    res.status(error.status || 500).json({
      error: error.message,
      details: error.data || null
    });
  }
});

/**
 * Get a Digiseller product by ID.
 */
app.get("/admin/digiseller/product/:id", adminGuard, async (req, res) => {
  try {
    const data = await digisellerRequest(`/products/${encodeURIComponent(req.params.id)}/data?lang=en-US&currency=USD`, {}, false);
    res.json(data);
  } catch (error) {
    console.error(error);
    res.status(error.status || 500).json({
      error: error.message,
      details: error.data || null
    });
  }
});

/**
 * Sync one Digiseller product into SoftStore.
 *
 * IMPORTANT:
 * Digiseller's documented seller API exposes catalog/product information,
 * but does not provide a general "download the seller's unsold content"
 * endpoint. Therefore this sync creates/updates catalog metadata only.
 * It does NOT pretend that Digiseller stock can be pulled as raw keys.
 */
app.post("/admin/sync/product/:digisellerProductId", adminGuard, async (req, res) => {
  try {
    const productId = req.params.digisellerProductId;
    const digi = await digisellerRequest(
      `/products/${encodeURIComponent(productId)}/data?lang=en-US&currency=USD`
    );

    const row = digi?.rows?.row?.[0] ?? digi?.content?.[0] ?? digi?.product ?? null;
    if (!row) {
      return res.status(404).json({
        error: "Digiseller product response did not contain a recognizable product row",
        response: digi
      });
    }

    const name = row.name || row.title || `Digiseller Product ${productId}`;
    const price = Number(row.price || row.price_usd || 1);
    const count = Number(row.num_in_stock ?? (row.in_stock ? 1 : 0));

    const body = {
      id_categories: Number(required("SOFTSTORE_DEFAULT_CATEGORY_ID")),
      name: String(name).slice(0, 255),
      meta_title: String(name).slice(0, 255),
      meta_description: `Imported from Digiseller product ${productId}`.slice(0, 1000),
      tags: "digiseller,imported,digital",
      text_page: String(row.info || row.description || `Imported from Digiseller product ${productId}`).slice(0, 10000),
      price: Math.max(1, Math.round(price * Number(process.env.PRICE_MULTIPLIER || 1))),
      count: Math.max(0, count),
      uuid: `digiseller-${productId}`,
      features: "Imported from Digiseller,Digital product,Automatic catalog sync",
      automated_message: "Your order has been received. Delivery is processed automatically when inventory is available."
    };

    const created = await softstoreRequest("/products", {
      method: "POST",
      body: JSON.stringify(body)
    });

    res.json({
      ok: true,
      note: "Catalog metadata synced. Delivery inventory is NOT imported from Digiseller.",
      digiseller_product_id: productId,
      softstore: created
    });
  } catch (error) {
    console.error(error);
    res.status(error.status || 500).json({
      error: error.message,
      details: error.data || null
    });
  }
});

/**
 * SoftStore payment webhook.
 */
app.post("/webhook/softstore", async (req, res) => {
  const payload = req.body || {};

  try {
    if (!payload.id_order || !payload.signature || !payload.delivery_url) {
      return res.status(400).json({ error: "Missing required webhook fields" });
    }

    if (!verifySoftStoreWebhook(payload)) {
      return res.status(403).json({ error: "Invalid signature" });
    }

    if (payload.payment_status !== "paid") {
      return res.json({ ok: true, ignored: true, reason: "payment_not_paid" });
    }

    // Fetch complete SoftStore order details.
    const order = await softstoreRequest(`/orders/info/${encodeURIComponent(payload.id_order)}`);

    console.log("Verified SoftStore order:", {
      id_order: payload.id_order,
      id_product: payload.id_product,
      order
    });

    const mode = process.env.DELIVERY_MODE || "disabled";
    const orderId = String(payload.id_order ?? order?.id_order ?? "");

    await sendOrderNotifications(order, payload);

    if (mode === "static") {
      const text = required("STATIC_DELIVERY_TEXT");

      if (orderId && deliveredOrderIds.has(orderId)) {
        console.warn(
          `[delivery] Duplicate static delivery suppressed for order ID ${orderId}.`
        );

        return res.json({
          ok: true,
          delivered: true,
          duplicate: true,
          mode: "static"
        });
      }

      await deliverToSoftStore(
        payload.delivery_url,
        text
      );

      if (orderId) {
        deliveredOrderIds.add(orderId);
      }

      return res.json({
        ok: true,
        delivered: true,
        mode: "static"
      });
    }

    // Deliberately do not fake Digiseller inventory retrieval.
    // The documented Digiseller API does not expose a generic endpoint
    // for reading the seller's unsold text/file content.
    return res.status(202).json({
      ok: true,
      delivered: false,
      mode: "disabled",
      message:
        "Webhook verified and order read successfully. Configure a real inventory source before enabling automatic delivery."
    });
  } catch (error) {
    console.error("Webhook error:", error);
    return res.status(error.status || 500).json({
      error: error.message,
      details: error.data || null
    });
  }
});

function validateSoftStoreDeliveryUrl(deliveryUrl) {
  let parsed;

  try {
    parsed = new URL(String(deliveryUrl));
  } catch {
    throw new Error("SoftStore delivery_url is not a valid URL.");
  }

  if (parsed.protocol !== "https:") {
    throw new Error("SoftStore delivery_url must use HTTPS.");
  }

  const allowedHosts = String(
    process.env.SOFTSTORE_ALLOWED_DELIVERY_HOSTS || ""
  )
    .split(",")
    .map(value => value.trim().toLowerCase())
    .filter(Boolean);

  if (!allowedHosts.length) {
    throw new Error(
      "SOFTSTORE_ALLOWED_DELIVERY_HOSTS is required before DELIVERY_MODE=static can be used."
    );
  }

  if (!allowedHosts.includes(parsed.hostname.toLowerCase())) {
    throw new Error(
      `Refusing to send SoftStore JWT to untrusted delivery host: ${parsed.hostname}`
    );
  }

  return parsed.toString();
}

async function deliverToSoftStore(deliveryUrl, text, download) {
  const safeDeliveryUrl =
    validateSoftStoreDeliveryUrl(deliveryUrl);

  const jwt = await getSoftStoreJwt();
  const body = { text };

  if (download) {
    body.download = download;
  }

  return jsonFetch(safeDeliveryUrl, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${jwt}`,
      "Content-Type": "application/json",
      Accept: "application/json"
    },
    body: JSON.stringify(body)
  });
}

app.listen(PORT, () => {
  console.log(`Integration server listening on port ${PORT}`);
});
