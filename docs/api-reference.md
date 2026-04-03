# API reference (quick index)

Base path: **`/v1`** (all routes below are relative to your host, e.g. `https://api.example.com/v1/...`).

Unless noted, requests use **`Content-Type: application/json`** and responses return JSON.

---

## Discovery & health

| Method | Path | Auth |
|--------|------|------|
| `GET` | `/healthz` | No |
| `GET` | `/v1` | No |
| `GET` | `/v1/openapi.json` | No |
| `GET` | `/v1/docs` | No (Swagger UI) |

---

## Authentication (`Authorization: Bearer <access_token>`)

| Method | Path | Auth |
|--------|------|------|
| `POST` | `/v1/customers/auth/register` | No |
| `POST` | `/v1/customers/auth/login` | No |
| `POST` | `/v1/customers/auth/google` | No |
| `POST` | `/v1/sellers/auth/login` | No |
| `POST` | `/v1/admins/auth/login` | No |

Auth routes use **stricter rate limiting** than the rest of the API (see `main.rs`).

---

## Catalog (public)

Approved listings only (`status = approved`). No authentication.

| Method | Path | Query / notes |
|--------|------|----------------|
| `GET` | `/v1/products` | `limit` (default 20, max 50), `offset`, optional `q` (title substring, case-insensitive) |
| `GET` | `/v1/products/{product_id}` | |

List responses include pagination: `items`, `total`, `limit`, `offset`.

---

## Products (seller)

| Method | Path | Principal |
|--------|------|-------------|
| `POST` | `/v1/sellers/me/products` | Seller JWT |
| `GET` | `/v1/sellers/me/products` | Seller JWT |
| `PATCH` | `/v1/sellers/me/products/{product_id}` | Seller JWT |
| `DELETE` | `/v1/sellers/me/products/{product_id}` | Seller JWT |

---

## Products (admin moderation)

| Method | Path | Principal |
|--------|------|-------------|
| `GET` | `/v1/admin/products/pending` | Admin JWT |
| `POST` | `/v1/admin/products/{product_id}/approve` | Admin JWT |
| `POST` | `/v1/admin/products/{product_id}/reject` | Admin JWT |

---

## Promotions

### Seller

| Method | Path | Principal |
|--------|------|-------------|
| `POST` | `/v1/sellers/me/promotions` | Seller JWT |
| `GET` | `/v1/sellers/me/promotions` | Seller JWT |
| `GET` | `/v1/sellers/me/promotions/{promotion_id}` | Seller JWT |
| `PATCH` | `/v1/sellers/me/promotions/{promotion_id}` | Seller JWT |
| `DELETE` | `/v1/sellers/me/promotions/{promotion_id}` | Seller JWT |

### Admin (platform-wide campaigns)

| Method | Path | Principal |
|--------|------|-------------|
| `POST` | `/v1/admin/promotions` | Admin JWT |
| `GET` | `/v1/admin/promotions` | Admin JWT |
| `GET` | `/v1/admin/promotions/{promotion_id}` | Admin JWT |
| `PATCH` | `/v1/admin/promotions/{promotion_id}` | Admin JWT |
| `DELETE` | `/v1/admin/promotions/{promotion_id}` | Admin JWT |

---

## Cart & checkout (customer)

| Method | Path | Principal | Notes |
|--------|------|-----------|--------|
| `GET` | `/v1/cart` | Customer JWT | |
| `PUT` | `/v1/cart/items` | Customer JWT | |
| `DELETE` | `/v1/cart/items/{product_id}` | Customer JWT | |
| `POST` | `/v1/cart/checkout` | Customer JWT | Requires **`Idempotency-Key`** (same as order create) |

---

## Customer profile

| Method | Path | Principal |
|--------|------|-------------|
| `GET` | `/v1/customers/me` | Customer JWT |
| `PATCH` | `/v1/customers/me` | Customer JWT |

`PATCH` accepts any of `full_name`, `phone`, `address` (send JSON `null` for `address` to clear). At least one field is required per request.

---

## Orders (customer)

| Method | Path | Principal | Headers |
|--------|------|-----------|---------|
| `GET` | `/v1/orders` | Customer JWT | `limit` (default 20, max 100), `offset` — paginated summaries: `items`, `total`, `limit`, `offset` |
| `POST` | `/v1/orders` | Customer JWT | **`Idempotency-Key`** (required) |
| `GET` | `/v1/orders/{order_id}` | Customer JWT | |
| `POST` | `/v1/orders/{order_id}/paystack/initialize` | Customer JWT | **`Idempotency-Key`** (required) |
| `POST` | `/v1/orders/{order_id}/payment/cash-on-delivery/confirm` | Customer JWT | **`Idempotency-Key`** (required) |
| `POST` | `/v1/orders/{order_id}/payment/installment/start` | Customer JWT | **`Idempotency-Key`** (required) |

---

## Payments (server / Paystack)

| Method | Path | Caller | Notes |
|--------|------|--------|--------|
| `POST` | `/v1/payments/paystack/webhook` | **Paystack servers only** | HMAC + IP allowlist; **not** for mobile/web apps |

---

## HTTP status codes (typical)

| Code | Meaning |
|------|---------|
| `200` | Success |
| `400` | Bad request (validation, missing header, business rule) |
| `401` | Missing/invalid token, or Paystack webhook signature failure |
| `403` | Authenticated but not allowed (wrong role / Casbin) |
| `404` | Resource not found |
| `409` | Conflict (duplicate idempotency semantics, wrong order state) |
| `500` | Server error |

Error body shape: **`ProblemDetails`** — see [frontend-integration.md](frontend-integration.md#error-format-problemdetails).

---

## Limits (selected)

| Item | Limit |
|------|--------|
| Default JSON body | 1 MiB (`DEFAULT_REQUEST_BODY_MAX`) |
| `Idempotency-Key` length | 256 chars max |
| Order line items | 100 max |
| Quantity per line | 10,000 max |
| JSON blobs (e.g. delivery address) | 16 KiB serialized max |
| Catalog page size | default 20, max 50 |
| Order list page size | default 20, max 100 |
| Catalog search `q` | 200 chars max (wildcards stripped) |

Exact constants: `src/http/limits.rs`.
