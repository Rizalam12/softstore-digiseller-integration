# SoftStore ↔ Digiseller Integration

This project is a Node.js middleware for connecting a SoftStore seller account with the Digiseller API.

## What it currently does

1. Authenticates to Digiseller using:
   - seller ID
   - Digiseller API key
   - SHA-256(API key + Unix timestamp)
2. Authenticates to SoftStore using the raw seller API key and exchanges it for a short-lived JWT.
3. Reads Digiseller catalog/product information.
4. Can create a corresponding catalog product in SoftStore.
5. Receives SoftStore paid-order webhooks.
6. Verifies the SoftStore webhook signature.
7. Reads the complete SoftStore order.
8. Has a test-only static delivery mode.

## Important limitation

The documented Digiseller seller API exposes product/catalog information and APIs for adding/changing/deleting product content, but it does not expose a generic endpoint that lets this middleware download the seller's unsold text/file inventory.

Therefore this project does NOT pretend that a Digiseller product automatically becomes a stock source for SoftStore.

If your real goal is:

SoftStore buyer pays → middleware purchases/obtains a product from Digiseller → middleware delivers it to SoftStore buyer

then the exact Digiseller purchasing/affiliate flow must be implemented according to the account type and permissions you have. Do not put buyer credentials or private product content into this project.

## 1. Install

Node.js 20+ is recommended.

```bash
npm install
```

## 2. Configure

Copy `.env.example` to `.env` and fill:

- SOFTSTORE_API_KEY
- DIGISELLER_SELLER_ID
- DIGISELLER_API_KEY
- SOFTSTORE_DEFAULT_CATEGORY_ID
- ADMIN_SECRET

Keep `.env` private and never commit it to GitHub.

## 3. Start locally

```bash
npm run dev
```

Health check:

```text
http://localhost:3000/health
```

## 4. Deploy

Deploy this project to a public HTTPS Node.js host such as your VPS or another service that provides a stable public URL.

Your SoftStore API URL should then be:

```text
https://YOUR-DOMAIN.example.com/webhook/softstore
```

Do NOT put the Digiseller API URL into SoftStore's API URL field.

## 5. SoftStore settings

Set:

API URL:

```text
https://YOUR-DOMAIN.example.com/webhook/softstore
```

Whitelist IP:

Use the public outbound IP of the server that sends the API requests, if SoftStore requires IP allowlisting for your account. Do not copy example IPs from the dashboard.

## 6. Digiseller token

The server automatically requests a Digiseller token when needed. Digiseller documents the token endpoint as:

POST https://api.digiseller.com/api/apilogin

The signature is SHA256(API key + timestamp), and the token is valid for about 2 hours.

## 7. Test Digiseller access

Send:

```bash
curl -H "X-ADMIN-SECRET: YOUR_ADMIN_SECRET" \
  https://YOUR-DOMAIN.example.com/admin/digiseller/products
```

## 8. Test one product lookup

```bash
curl -H "X-ADMIN-SECRET: YOUR_ADMIN_SECRET" \
  https://YOUR-DOMAIN.example.com/admin/digiseller/product/PRODUCT_ID
```

## 9. Sync catalog metadata

```bash
curl -X POST \
  -H "X-ADMIN-SECRET: YOUR_ADMIN_SECRET" \
  https://YOUR-DOMAIN.example.com/admin/sync/product/PRODUCT_ID
```

Before doing this, make sure `SOFTSTORE_DEFAULT_CATEGORY_ID` is a real SoftStore category.

## 10. Test SoftStore webhook without real delivery

Leave:

```text
DELIVERY_MODE=disabled
```

The server will validate the signature and read the order but will not send fake product data to a customer.

For a controlled test only, you can set:

```text
DELIVERY_MODE=static
STATIC_DELIVERY_TEXT=TEST DELIVERY
```

Never use static delivery in production.

## Production architecture

```text
Customer
   |
   v
SoftStore
   |
   | paid webhook
   v
Your Node.js middleware
   |
   +--> verify SoftStore signature
   |
   +--> read SoftStore order
   |
   +--> map SoftStore product -> Digiseller product
   |
   +--> obtain legitimate inventory/product through an allowed Digiseller flow
   |
   +--> deliver to SoftStore delivery_url
   |
   v
Customer
```

## Security

- Never expose `SOFTSTORE_API_KEY`.
- Never expose `DIGISELLER_API_KEY`.
- Never commit `.env`.
- Use HTTPS.
- Keep admin endpoints protected.
- Verify the SoftStore webhook signature before processing an order.
- Add idempotency/order locking before production use so the same order cannot be delivered twice.
