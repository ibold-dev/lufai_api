# Frontend & mobile integration guide

This document is for **web, Flutter, and native app** developers connecting to **lufai_api**. It explains authentication, errors, idempotency, payment flows, order lifecycle, and **best practices** so your UI behaves correctly and safely.

**Companion:** [api-reference.md](api-reference.md) for a route index. **Machine-readable contract:** `GET /v1/openapi.json` and Swagger UI at `/v1/docs`.

---

## Table of contents

1. [Base URL and versioning](#base-url-and-versioning)
2. [Content type and encoding](#content-type-and-encoding)
3. [Error format (`ProblemDetails`)](#error-format-problemdetails)
4. [Authentication (JWT)](#authentication-jwt)
5. [Authorization model (roles)](#authorization-model-roles)
6. [Idempotency (`Idempotency-Key`)](#idempotency-idempotency-key)
7. [Rate limiting](#rate-limiting)
8. [CORS and browser clients](#cors-and-browser-clients)
9. [Orders: fields your UI should read](#orders-fields-your-ui-should-read)
10. [Payment method identifiers](#payment-method-identifiers)
11. [Order status lifecycle](#order-status-lifecycle)
12. [Payment flows (detailed)](#payment-flows-detailed)
13. [Paystack webhook (for your understanding only)](#paystack-webhook-for-your-understanding-only)
14. [Products, cart, and promotions (summary)](#products-cart-and-promotions-summary)
15. [Best practices checklist](#best-practices-checklist)
16. [Example: electronic payment UX](#example-electronic-payment-ux)
17. [Example: COD and installment UX](#example-cod-and-installment-ux)
18. [Troubleshooting](#troubleshooting)

---

## Base URL and versioning

- All business endpoints live under **`/v1`**.
- Example: `https://api.yourdomain.com/v1/orders`
- **`GET /v1`** returns `{ "status": "ok", "version": "v1" }` — useful for connectivity checks.
- **`GET /healthz`** is outside `/v1` and is intended for load balancers / k8s probes.

Do not hardcode absolute paths without the `/v1` prefix unless you are calling `/healthz`.

---

## Content type and encoding

- Send JSON with header: **`Content-Type: application/json`** for bodies.
- Responses are JSON unless the route explicitly returns something else (webhook may return plain status in edge cases; most JSON APIs return `application/json`).

---

## Error format (`ProblemDetails`)

Failed requests return a JSON body compatible with **RFC 7807-style** problem details (see `src/http/error.rs`):

```json
{
  "type": "https://example.com/problems",
  "title": "bad_request",
  "status": 400,
  "detail": "human-readable explanation"
}
```

| Field | Meaning |
|-------|---------|
| `type` | URI placeholder (currently fixed in code) |
| `title` | Short machine-ish tag: `bad_request`, `unauthorized`, `forbidden`, `not_found`, `conflict`, `internal_error` |
| `status` | HTTP status code (duplicate of the response status) |
| `detail` | Human-readable message; **show to users when appropriate**, or map to localized strings |

**How to handle in UI:**

- **`401` (`unauthorized`)** — No/invalid token: redirect to login or refresh token flow.
- **`403` (`forbidden`)** — Wrong role or policy: show “not allowed” (user is logged in but cannot do this).
- **`400` (`bad_request`)** — Validation or business rule: show `detail` (or a mapped message).
- **`404` (`not_found`)** — Resource missing or not visible to this user.
- **`409` (`conflict`)** — Often idempotency or state conflict (e.g. payment path already chosen).
- **`500` (`internal_error`)** — Server issue: show generic error, offer retry, log reference.

---

## Authentication (JWT)

### Obtaining a token

Use the appropriate **login or register** route for the actor type:

| Actor | Register | Login |
|-------|----------|-------|
| Customer | `POST /v1/customers/auth/register` | `POST /v1/customers/auth/login` |
| Customer (Google) | — | `POST /v1/customers/auth/google` |
| Seller | — | `POST /v1/sellers/auth/login` (`email` + `login_code`) |
| Affiliate | — | `POST /v1/affiliates/auth/login` (`email` + `login_code`) |
| Admin | — | `POST /v1/admins/auth/login` |

Successful responses include an **`AuthResponse`** with:

- **`access_token`** — JWT string
- **`token_type`** — `"bearer"`
- **`expires_in`** — seconds (from server config, default 24h)
- **`subject`** — principal id, e.g. `customer:<uuid>`, `seller:<uuid>`, `admin:<uuid>`

### Sending the token

For every protected route, send:

```http
Authorization: Bearer <access_token>
```

**Do not** send the token in query strings or client-side logs.

### Subject format

JWT `sub` (and response `subject`) looks like:

- `customer:550e8400-e29b-41d4-a716-446655440000`
- `seller:...`
- `admin:...`

Use this to **debug** which role the backend thinks you are. The API enforces role-specific routes (e.g. only customer JWT works for `/v1/cart`).

### Token lifetime and refresh

The API issues **access tokens** with TTL from `JWT_ACCESS_TOKEN_TTL_SECS` (default **86400** seconds). There is **no refresh token flow documented in this API** — when you get `401`, the client should **re-authenticate** (login again) unless you add a refresh flow separately.

### Google sign-in

When `GOOGLE_CLIENT_ID` is configured on the server, customers can call `POST /v1/customers/auth/google` with an ID token (`id_token` or `credential` field). If the server does not configure Google, that route will fail.

---

## Authorization model (roles)

- **Customers** can access cart, orders they own, and payment initialization for their orders.
- **Sellers** can manage their own products and seller-scoped promotions.
- **Admins** can moderate products and manage platform promotions.

Authorization is enforced with **JWT** (correct route prefix) and **Casbin** policies (`casbin_policy.csv`). If you get **`403`**, you are authenticated as the wrong principal type or the resource is not yours.

---

## Idempotency (`Idempotency-Key`)

Several **mutating** operations require a header:

```http
Idempotency-Key: <opaque string>
```

**Rules:**

- Max length **256** characters (`MAX_IDEMPOTENCY_KEY_LEN`).
- Must be **non-empty**.
- **Same logical operation** must reuse the **same key** when retrying after network failure (otherwise you may create duplicate side effects where the API allows duplicates).

### Operations that require `Idempotency-Key` (current implementation)

| Operation | Endpoint |
|-----------|----------|
| Create order | `POST /v1/orders` |
| Cart checkout (creates order) | `POST /v1/cart/checkout` |
| Paystack initialize | `POST /v1/orders/{order_id}/paystack/initialize` |
| Confirm COD | `POST /v1/orders/{order_id}/payment/cash-on-delivery/confirm` |
| Start installment | `POST /v1/orders/{order_id}/payment/installment/start` |

### Best practice for generating keys

- Generate a **new UUID (v4) or ULID** per **user gesture** (“Place order”, “Pay now”, “Confirm COD”).
- **Persist** the key until the request succeeds or the user cancels — so retries send the **same** key.
- **Never** reuse the same key for a **different** order or a different payment attempt intent.

If you send the **same** key again for the **same** idempotent operation, the API returns the **same outcome** (e.g. same `order_id` for order creation).

---

## Rate limiting

The server uses **tower-governor** (IP-based):

- **Auth routes** (`/v1/customers/auth/*`, `/v1/sellers/auth/*`, `/v1/affiliates/auth/*`, `/v1/admins/auth/*`) use a **stricter** limit (`GovernorConfig::secure()`).
- **Other `/v1` business routes** use the default profile.

**UI behavior:** On **429** (if exposed by your deployment) or repeated failures, **back off** and avoid tight retry loops.

---

## CORS and browser clients

This API does **not** configure CORS in the snippets shown in `main.rs`. If a **browser** calls the API directly from another origin:

- You may need **CORS headers** on a reverse proxy (nginx, Cloudflare, API gateway), **or**
- Use a **same-origin BFF** (Next.js route handlers, etc.) that holds `JWT_SECRET` / Paystack secret server-side.

**Mobile and Flutter** apps are not subject to CORS when calling the API directly.

---

## Storefront: catalog, profile, order history

| Need | Endpoint | Auth |
|------|----------|------|
| Browse / search approved products | `GET /v1/products` (`limit`, `offset`, optional `q`) | No |
| Product detail (PDP) | `GET /v1/products/{product_id}` | No |
| Account profile | `GET` / `PATCH /v1/customers/me` | Customer JWT |
| Order list (summaries) | `GET /v1/orders` (`limit`, `offset`) | Customer JWT |
| Order detail (lines, totals) | `GET /v1/orders/{order_id}` | Customer JWT |

Use the **list** endpoints for grids and history; use **`GET /v1/orders/{order_id}`** when you need full line items and payment snapshot fields.

---

## Admin listing endpoints

Admin JWT can fetch paginated identity lists:

| Endpoint | Purpose |
|----------|---------|
| `GET /v1/admin/users?limit=&offset=` | Combined user identities across `customer`, `seller`, `affiliate` |
| `GET /v1/admin/sellers?limit=&offset=` | Sellers list |
| `GET /v1/admin/affiliates?limit=&offset=` | Affiliates list |

These endpoints return only operational profile fields (ids/emails/timestamps and role/revocation flags), never login hashes or raw login codes.

---

## Orders: fields your UI should read

`GET /v1/orders/{order_id}` returns an **`OrderResponse`** (see OpenAPI). Important fields for UI:

| Field | Purpose |
|-------|---------|
| `status` | Drives screens (awaiting payment, paid, COD, installment, etc.) |
| `total_cents`, `currency` | Display totals |
| `allowed_payment_methods` | **Snapshot** at order creation: which methods are valid for this order (intersection across lines) |
| `payment_channel` | Which path the customer chose: `electronic`, `cash_on_delivery`, `installment`, or `null` if not chosen yet |
| `installment_plan` | JSON blob when installment was started; structure matches `StartInstallmentRequest` + storage |
| `items[]` | Line items with `list_unit_price_cents`, `unit_price_cents`, `promotion_id` |

**Always** use `allowed_payment_methods` from the **order** when deciding which buttons to show — do not infer only from catalog, because promotions can restrict methods.

---

## Payment method identifiers

These are **string identifiers** returned by the API and used in product/promotion configuration:

| Value | Meaning |
|-------|---------|
| `electronic` | Online/card payment via **Paystack** (initialize flow) |
| `cash_on_delivery` | Cash-on-delivery confirmation flow |
| `installment` | Installment plan start flow (metadata stored on order) |

---

## Order status lifecycle

Statuses are **strings** stored on the order. Common values include:

| Status | Typical meaning |
|--------|-----------------|
| `awaiting_payment` | Order created; customer must pick a payment path |
| `payment_initialized` | Paystack checkout was initialized (`authorization_url` issued) |
| `paid` | **Electronic** payment confirmed (Paystack webhook + verification) |
| `cod_confirmed` | Customer confirmed **cash on delivery** |
| `installment_started` | Customer started **installment**; plan JSON stored |

**Conflicts:** If the order is **not** `awaiting_payment`, alternate flows (COD, installment) and a second Paystack init may return **`409`** with a message about payment choice already made.

**Your UI should:**

1. Treat **`GET /v1/orders/{id}`** as the source of truth for `status`.
2. After Paystack redirect, **poll** the order until `paid` (or show error) — **do not** assume success from the return URL alone.

---

## Payment flows (detailed)

### A. Electronic (Paystack)

1. Customer has order in **`awaiting_payment`** with `electronic` ∈ `allowed_payment_methods`.
2. Client calls **`POST /v1/orders/{order_id}/paystack/initialize`** with **`Idempotency-Key`** and `Authorization`.
3. Response includes **`authorization_url`**, **`access_code`**, **`paystack_reference`**.
4. Open **`authorization_url`** in a **WebView** or **system browser** (mobile).
5. Backend receives Paystack webhook; on success marks order **`paid`**.
6. Client polls **`GET /v1/orders/{order_id}`** until `status == "paid"` (or timeout → support).

**Errors:**

- If `electronic` ∉ `allowed_payment_methods`, initialize returns **400** with a message that electronic payment is not allowed.

### B. Cash on delivery

1. `cash_on_delivery` ∈ `allowed_payment_methods`.
2. Order must be **`awaiting_payment`**.
3. `POST /v1/orders/{order_id}/payment/cash-on-delivery/confirm` with **`Idempotency-Key`**.
4. Order becomes **`cod_confirmed`**, `payment_channel` = `cash_on_delivery`.

### C. Installment

1. `installment` ∈ `allowed_payment_methods`.
2. Order **`awaiting_payment`**.
3. `POST /v1/orders/{order_id}/payment/installment/start` with JSON body:

```json
{
  "num_installments": 6,
  "notes": "optional"
}
```

`num_installments` must be **2–60** (server validation).

4. Order becomes **`installment_started`**, `payment_channel` = `installment`, `installment_plan` stores the payload.

---

## Paystack webhook (for your understanding only)

- **URL:** `POST /v1/payments/paystack/webhook`
- **Called by:** Paystack servers, **not** by your app.
- **Purpose:** Verify `charge.success`, match `reference` to `payment_attempt`, verify amount, mark order **`paid`**.
- **Security:** HMAC signature header + IP allowlist on the server.

**Frontend rule:** Never call the webhook; never put `PAYSTACK_SECRET_KEY` in the client.

---

## Products, cart, and promotions (summary)

- **Sellers** create products (`pending` until admin approves). There is **no public “list all products”** route in the default OpenAPI list — UIs often get product IDs from **deep links**, **search service**, or **admin/seller tools** depending on your deployment.
- **Cart** is per-customer JWT: `GET/PUT/DELETE` under `/v1/cart`.
- **Checkout:** `POST /v1/cart/checkout` creates an order (requires idempotency) and clears the cart on success.
- **Promotions:** Sellers/admins configure discounts; pricing engine applies promotions at order creation and sets line `promotion_id` and `allowed_payment_methods` according to product + promotion rules.

For details, use **OpenAPI** schemas per route.

---

## Best practices checklist

### Security

- [ ] Store JWT in **secure storage** (Keychain / Keystore / encrypted web storage).
- [ ] Never log **tokens** or **Idempotency-Key** in production analytics.
- [ ] Never embed **Paystack secret** or **JWT secret** in client apps.
- [ ] Use **HTTPS** for all API calls.

### Reliability

- [ ] Use **idempotency** on all required routes and **retry** with the **same key** on transient failures.
- [ ] Implement **exponential backoff** on 5xx and network errors.
- [ ] For Paystack, **poll order status** after return from checkout.

### UX

- [ ] Show **loading** during payment initialization and after redirect.
- [ ] Map **`detail`** from `ProblemDetails` to user-friendly copy where possible.
- [ ] Hide payment buttons not present in `allowed_payment_methods` on the **order** object.

### Testing

- [ ] Use **`/v1/docs`** to try requests with a valid token.
- [ ] Test **duplicate** order creation with the **same** `Idempotency-Key` → same `order_id`.

---

## Example: electronic payment UX

1. User taps “Pay with card”.
2. Generate `idempotencyKey = uuid()`.
3. `POST /v1/orders/{id}/paystack/initialize` with `Idempotency-Key: idempotencyKey`.
4. On 200, open `authorization_url`.
5. Show “Processing payment…”
6. Poll `GET /v1/orders/{id}` every 2–3s until `status == paid` or timeout (e.g. 2–5 minutes).
7. On `paid`, show success screen.

---

## Example: COD and installment UX

**COD**

1. Show “Pay on delivery” only if `cash_on_delivery` ∈ `order.allowed_payment_methods`.
2. On confirm: `POST .../payment/cash-on-delivery/confirm` with new idempotency key.
3. On success, show order confirmation with `status: cod_confirmed`.

**Installment**

1. Show only if `installment` ∈ `allowed_payment_methods`.
2. Collect `num_installments` (and optional notes).
3. `POST .../payment/installment/start` with body + idempotency key.
4. Show confirmation with `installment_plan` echoed from order.

---

## Troubleshooting

| Symptom | Likely cause |
|---------|----------------|
| `401` on all routes | Token missing/expired/wrong `Authorization` header format |
| `403` on seller route | Logged in as **customer** (or vice versa) |
| `409` on payment | Order not `awaiting_payment` (e.g. Paystack already started) |
| `400` on Paystack init | `electronic` not in `allowed_payment_methods` |
| Order never becomes `paid` | Webhook misconfigured, wrong secret, or Paystack not sending `charge.success` |
| Duplicate orders | Different `Idempotency-Key` on retries for order create |

---

## Changelog

Maintain this section when you change behavior:

| Date | Change |
|------|--------|
| (add) | Initial documentation from current `lufai_api` sources |

When in doubt, **trust the code** and **`/v1/openapi.json`** over this file if they diverge.
