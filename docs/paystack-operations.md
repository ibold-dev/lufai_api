# Paystack: operations & backend configuration

This page is for **DevOps / backend** staff configuring Paystack and deploying **lufai_api**. Client apps should read [frontend-integration.md](frontend-integration.md).

## Webhook URL

Configure Paystack to send webhooks to:

```text
POST https://<your-public-api-host>/v1/payments/paystack/webhook
```

- The path is **under `/v1`** (see `main.rs` nesting).
- The handler is **`payments::routes::paystack_webhook`** in `src/payments/routes.rs`.

## Security checks implemented by the API

1. **Source IP allowlist** — Only requests from Paystack’s published IPs are accepted (see `PAYSTACK_IP_ALLOWLIST` in `src/payments/routes.rs`). Update this list if Paystack changes IPs.
2. **`x-paystack-signature`** — HMAC-SHA512 of the **raw request body** using `PAYSTACK_SECRET_KEY`. Must match Paystack’s signature.
3. **Event type** — Only `charge.success` is processed; other events return `200` to avoid unnecessary retries.
4. **Idempotent processing** — Webhook events are deduplicated by `(provider, reference)` in `webhook_events`.
5. **Amount verification** — By default, the server calls Paystack’s **verify transaction** API to confirm the amount before marking payment verified.  
   - Local/testing: `PAYSTACK_WEBHOOK_DISABLE_SDK_VERIFY=1` or `true` disables SDK verification (see code comments — **not for production**).

## Environment variables (Paystack-related)

| Variable | Purpose |
|----------|---------|
| `PAYSTACK_SECRET_KEY` | Secret key; required for initialize + webhook verification |
| `PAYSTACK_CALLBACK_URL` | Optional; passed to Paystack initialize (default placeholder in code if unset) |
| `PAYSTACK_WEBHOOK_DISABLE_SDK_VERIFY` | Test-only: skip SDK amount verification |

## What the webhook updates

On successful verification for a known `payment_attempt` reference:

- **`payment_attempt.status`** → `verified` (with metadata)
- **`orders.status`** → `paid`
- **`webhook_events.processed_at`** set

If the verified amount does not match the stored attempt, the attempt is marked **`failed`** with diagnostic JSON.

## TLS and network

- Paystack must reach your **public HTTPS** endpoint.
- If you terminate TLS at a load balancer, ensure the app still receives the correct client IP **or** adjust IP allowlisting / proxy trust as appropriate for your deployment.

## Related client behavior

- UIs should **poll** `GET /v1/orders/{id}` for `status: paid` after Paystack redirect.
- The mobile app **never** calls the webhook endpoint.
