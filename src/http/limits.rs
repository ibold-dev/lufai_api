//! Size and shape limits for untrusted input (DoS / abuse mitigation).

/// Default request body size (JSON, etc.). Applied via [`axum::extract::DefaultBodyLimit`].
pub const DEFAULT_REQUEST_BODY_MAX: usize = 1024 * 1024; // 1 MiB

/// Paystack webhook raw body (HMAC is over full body; keep bounded).
pub const PAYSTACK_WEBHOOK_BODY_MAX: usize = 512 * 1024; // 512 KiB

/// Serialized JSON for `jsonb` blobs (delivery address, dimensions, etc.).
pub const MAX_JSON_VALUE_BYTES: usize = 16 * 1024; // 16 KiB

/// Max line items per order.
pub const MAX_ORDER_LINE_ITEMS: usize = 100;

/// Max units per line item (abuse / overflow mitigation).
pub const MAX_LINE_ITEM_QUANTITY: i32 = 10_000;

/// `Idempotency-Key` header (RFC 7239-style; keep short).
pub const MAX_IDEMPOTENCY_KEY_LEN: usize = 256;

/// Product title / short text fields.
pub const MAX_PRODUCT_TITLE_LEN: usize = 500;

/// Product description (longer copy).
pub const MAX_PRODUCT_DESCRIPTION_LEN: usize = 20_000;

/// Password register/login (Argon2; cap to limit CPU DoS).
pub const MAX_PASSWORD_BYTES: usize = 256;

/// Minimum JWT signing secret length (bytes).
pub const MIN_JWT_SECRET_BYTES: usize = 32;
