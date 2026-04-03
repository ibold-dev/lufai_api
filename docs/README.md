# Documentation index

## Client integration (recommended order)

1. **[frontend-integration.md](frontend-integration.md)** — How web and mobile clients should authenticate, handle errors, use idempotency, choose payment methods, and poll order state. Includes security and UX checklists.
2. **[api-reference.md](api-reference.md)** — Quick reference: all routes, methods, and which calls need `Authorization` or `Idempotency-Key`.
3. **[paystack-operations.md](paystack-operations.md)** — DevOps: webhook URL, IP allowlist concept, env vars, what the webhook updates.

## Source of truth

- **OpenAPI:** `GET /v1/openapi.json` (generated from Rust with `utoipa`)
- **Swagger UI:** `/v1/docs`
- **Implementation:** `src/` — route modules mirror URL paths under `main.rs` nesting

## Updating these docs

When you add or change routes, update:

- `src/openapi.rs` (path registration)
- `docs/api-reference.md` (endpoint table)
- `docs/frontend-integration.md` (if behavior or best practices change)
