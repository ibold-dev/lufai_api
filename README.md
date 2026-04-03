# lufai_api

Rust marketplace API (Axum, SeaORM, PostgreSQL, JWT, Casbin, Paystack). Customers, sellers, and admins interact through versioned JSON endpoints under **`/v1`**.

## Documentation for client apps (web / Flutter / mobile)

| Document | Description |
|----------|-------------|
| **[docs/frontend-integration.md](docs/frontend-integration.md)** | **Start here:** auth, errors, idempotency, payment flows, order lifecycle, security, and best practices for UI teams. |
| **[docs/api-reference.md](docs/api-reference.md)** | Endpoint index, required headers, and status codes. |
| **[docs/paystack-operations.md](docs/paystack-operations.md)** | Webhook URL, security checks, env vars (for operators). |
| **[docs/README.md](docs/README.md)** | Documentation index and quick links. |

## API discovery

- **OpenAPI JSON:** `GET /v1/openapi.json`
- **Swagger UI:** `GET /v1/docs` (interactive explorer)
- **API root:** `GET /v1` (returns `{ "status": "ok", "version": "v1" }`)
- **Health:** `GET /healthz` (liveness; no version prefix)

## Running locally

Prerequisites: Rust toolchain, PostgreSQL, environment variables (see below).

```bash
# Example: run migrations then start the server
export DATABASE_URL="postgres://user:pass@localhost:5432/lufai"
export JWT_SECRET="at-least-32-bytes-long-secret-key-here"
cargo run
```

Default listen address: **`0.0.0.0:3000`** (override with `PORT`).

### Required / common environment variables

| Variable | Purpose |
|----------|---------|
| `DATABASE_URL` | PostgreSQL connection string |
| `JWT_SECRET` | Min 32 bytes; signs access tokens |
| `JWT_ISSUER` | Optional; default `lufai_api` |
| `JWT_ACCESS_TOKEN_TTL_SECS` | Optional; default `86400` (24h) |
| `PAYSTACK_SECRET_KEY` | Server-side Paystack secret (initialize + webhook verification) |
| `PAYSTACK_CALLBACK_URL` | Optional; Paystack callback URL |
| `GOOGLE_CLIENT_ID` | Optional; enables Google sign-in for customers when set |

See `AppState::from_db` in `src/state.rs` for full loading logic.

## License / project

Internal marketplace API; contract details are defined by the OpenAPI spec and the guides in `docs/`.
