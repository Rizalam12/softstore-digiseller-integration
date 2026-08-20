import express from "express";
import crypto from "node:crypto";
import "dotenv/config";

const app = express();
app.use(express.json({ limit: "1mb" }));

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
    const error = new Error(
      `HTTP ${response.status} from ${url}: ${JSON.stringify(data)}`
    );
    error.status = response.status;
    error.data = data;
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

async function digisellerRequest(path, options = {}) {
  const token = await getDigisellerToken();
  const separator = path.includes("?") ? "&" : "?";
  return jsonFetch(`${DIGISELLER_API_BASE}${path}${separator}token=${encodeURIComponent(token)}`, {
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

  return crypto.timingSafeEqual(
    Buffer.from(expected),
    Buffer.from(String(payload.signature ?? ""))
  );
}

function adminGuard(req, res, next) {
  const expected = required("ADMIN_SECRET");
  const supplied = req.get("X-ADMIN-SECRET");
  if (!supplied || supplied !== expected) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  next();
}

app.get("/health", (_req, res) => {
  res.json({ ok: true, service: "softstore-digiseller-integration" });
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
    const data = await digisellerRequest(`/products/${encodeURIComponent(req.params.id)}/data?lang=en-US&currency=USD`);
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

    if (mode === "static") {
      const text = required("STATIC_DELIVERY_TEXT");

      await deliverToSoftStore(payload.delivery_url, text);

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

async function deliverToSoftStore(deliveryUrl, text, download) {
  const jwt = await getSoftStoreJwt();
  const body = { text };
  if (download) body.download = download;

  return jsonFetch(deliveryUrl, {
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
