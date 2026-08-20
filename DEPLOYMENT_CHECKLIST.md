# Deployment checklist

## A. Digiseller

[ ] Obtain your Digiseller seller ID.

[ ] Obtain/enable the Digiseller API key with the permissions required for your intended operations.

[ ] Keep the API key private.

[ ] Confirm the product IDs you want to synchronize.

## B. SoftStore

[ ] Obtain the raw SoftStore seller API key.

[ ] Find a valid SoftStore category ID.

[ ] Deploy this middleware on a public HTTPS server.

[ ] Set SoftStore API URL to:

https://YOUR-DOMAIN.example.com/webhook/softstore

[ ] Add the server's correct public IP to the SoftStore whitelist if required.

## C. Environment variables

[ ] SOFTSTORE_API_KEY

[ ] DIGISELLER_SELLER_ID

[ ] DIGISELLER_API_KEY

[ ] SOFTSTORE_DEFAULT_CATEGORY_ID

[ ] ADMIN_SECRET

## D. Tests

[ ] GET /health

[ ] GET /admin/digiseller/products

[ ] GET /admin/digiseller/product/:id

[ ] POST /admin/sync/product/:id

[ ] Make a small/test SoftStore order.

[ ] Confirm webhook signature is accepted.

[ ] Confirm the order is read.

[ ] Only after a legitimate inventory/delivery adapter is available, enable production delivery.

## E. Do not do

[ ] Do not paste the Digiseller API URL into SoftStore's API URL field.

[ ] Do not copy the example whitelist IPs.

[ ] Do not put API keys in JavaScript source.

[ ] Do not enable fake/static delivery for real customers.
