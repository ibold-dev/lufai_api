use axum::{Router, routing::post};
use axum::{
    extract::{ConnectInfo, Extension},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use paystack::{PaystackClient, ReqwestClient};
use serde_json::Value;
use sha2::Sha512;
use std::net::SocketAddr;

use hmac::{Hmac, Mac};
use sqlx::Row;
use uuid::Uuid;

use crate::{http::error::ApiError, state::AppState};

const PAYSTACK_WEBHOOK_PROVIDER: &str = "paystack";

const PAYSTACK_IP_ALLOWLIST: [&str; 3] = ["52.31.139.75", "52.49.173.169", "52.214.14.220"];

type HmacSha512 = Hmac<Sha512>;

pub fn routes() -> Router {
    Router::new().route("/payments/paystack/webhook", post(paystack_webhook))
}

fn is_allowed_ip(peer: SocketAddr) -> bool {
    PAYSTACK_IP_ALLOWLIST
        .iter()
        .any(|allowed| allowed == &peer.ip().to_string())
}

fn header_signature(headers: &HeaderMap) -> std::result::Result<String, ApiError> {
    let sig = headers
        .get("x-paystack-signature")
        .ok_or_else(ApiError::unauthorized)?;
    let sig = sig.to_str().map_err(|_| ApiError::unauthorized())?;
    Ok(sig.to_string())
}

/// When set to `1` or `true`, the webhook uses signed payload amounts only (for local tests).
/// **Do not set in production** — production should confirm `charge.success` via the SDK.
fn paystack_webhook_sdk_verify_disabled() -> bool {
    std::env::var("PAYSTACK_WEBHOOK_DISABLE_SDK_VERIFY")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

/// Confirms the charge with Paystack using [`TransactionEndpoints::verify_transaction`].
async fn paystack_verified_amount_cents(reference: &str, secret: &str) -> Option<i64> {
    let client = PaystackClient::<ReqwestClient>::new(secret.to_string());
    let res = client.transactions.verify_transaction(reference).await.ok()?;
    if !res.status {
        return None;
    }
    let data = res.data?;
    if data.status != "success" {
        return None;
    }
    Some(i64::from(data.amount))
}

fn verify_paystack_signature(
    secret: &str,
    body_bytes: &[u8],
    signature_hex: &str,
) -> std::result::Result<(), ApiError> {
    let mut mac = HmacSha512::new_from_slice(secret.as_bytes())
        .map_err(|e| ApiError::internal(format!("hmac init failed: {e}")))?;
    mac.update(body_bytes);
    let computed = hex::encode(mac.finalize().into_bytes());

    // Header is a hex string; compare case-insensitively.
    if computed.eq_ignore_ascii_case(signature_hex) {
        Ok(())
    } else {
        Err(ApiError::unauthorized())
    }
}

#[utoipa::path(
    post,
    path = "/v1/payments/paystack/webhook",
    responses(
        (status = 200, description = "Webhook processed (idempotent).")
    )
)]
pub(crate) async fn paystack_webhook(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Extension(state): Extension<AppState>,
    headers: HeaderMap,
    body: axum::body::Body,
) -> impl IntoResponse {
    // Always respond quickly; any processing failure should not cause repeated side effects.
    if !is_allowed_ip(peer) {
        return StatusCode::FORBIDDEN;
    }

    let signature_hex = match header_signature(&headers) {
        Ok(s) => s,
        Err(_) => return StatusCode::UNAUTHORIZED,
    };

    let paystack_secret = match std::env::var("PAYSTACK_SECRET_KEY") {
        Ok(v) => v,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR,
    };

    let body_bytes = match axum::body::to_bytes(body, usize::MAX).await {
        Ok(bytes) => bytes,
        Err(_) => return StatusCode::BAD_REQUEST,
    };

    if verify_paystack_signature(&paystack_secret, &body_bytes, &signature_hex).is_err() {
        return StatusCode::UNAUTHORIZED;
    }

    let payload: Value = match serde_json::from_slice(&body_bytes) {
        Ok(v) => v,
        Err(_) => return StatusCode::BAD_REQUEST,
    };

    let event_type = payload
        .get("event")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();

    // For v1 we only handle successful charges.
    if event_type != "charge.success" {
        return StatusCode::OK;
    }

    let reference = payload
        .pointer("/data/reference")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let Some(reference) = reference else {
        return StatusCode::BAD_REQUEST;
    };

    let amount_cents = if paystack_webhook_sdk_verify_disabled() {
        payload
            .pointer("/data/amount")
            .and_then(|v| v.as_i64())
            .unwrap_or_default()
    } else {
        match paystack_verified_amount_cents(&reference, &paystack_secret).await {
            Some(a) => a,
            None => return StatusCode::OK,
        }
    };

    // Process-once + atomic state updates.
    // Intentionally always return 200 on processing errors to avoid retries
    // causing partial side-effects.
    let mut tx = match state.pool.begin().await {
        Ok(tx) => tx,
        Err(_) => return StatusCode::OK,
    };

    // Insert de-dup record. If it already exists, return immediately.
    let inserted = match sqlx::query(
        "INSERT INTO webhook_events (provider, event_type, reference, raw_payload, processed_at)
         VALUES ($1, $2, $3, $4, NULL)
         ON CONFLICT (provider, reference) DO NOTHING",
    )
    .bind(PAYSTACK_WEBHOOK_PROVIDER)
    .bind(&event_type)
    .bind(&reference)
    .bind(&payload)
    .execute(&mut *tx)
    .await
    {
        Ok(r) => r,
        Err(_) => {
            let _ = tx.commit().await;
            return StatusCode::OK;
        }
    };

    if inserted.rows_affected() == 0 {
        let _ = tx.commit().await;
        return StatusCode::OK;
    }

    let payment_row = match sqlx::query(
        "SELECT id, order_id, amount_cents, status
         FROM payment_attempts
         WHERE paystack_reference = $1
         FOR UPDATE",
    )
    .bind(&reference)
    .fetch_optional(&mut *tx)
    .await
    {
        Ok(r) => r,
        Err(_) => {
            let _ = tx.commit().await;
            return StatusCode::OK;
        }
    };

    let Some(payment_row) = payment_row else {
        let _ = tx.commit().await;
        return StatusCode::OK;
    };

    let payment_attempt_id: Uuid = payment_row.try_get("id").unwrap_or_default();
    let order_id: Uuid = payment_row.try_get("order_id").unwrap_or_default();
    let expected_amount: i64 = payment_row.try_get("amount_cents").unwrap_or_default();
    let current_status: String = payment_row.try_get("status").unwrap_or_default();

    if amount_cents != expected_amount {
        let _ = sqlx::query(
            "UPDATE payment_attempts
             SET status = 'failed', updated_at = now(), raw_payload = $1
             WHERE id = $2",
        )
        .bind(serde_json::json!({
            "error": "amount mismatch",
            "expected_amount": expected_amount,
            "verified_amount": amount_cents,
            "reference": reference,
        }))
        .bind(payment_attempt_id)
        .execute(&mut *tx)
        .await;

        let _ = tx.commit().await;
        return StatusCode::OK;
    }

    // If already verified, still ensure order is marked paid.
    if current_status != "verified" {
        let _ = sqlx::query(
            "UPDATE payment_attempts
             SET status = 'verified',
                 updated_at = now(),
                 raw_payload = COALESCE(raw_payload, '{}'::jsonb) || $1::jsonb
             WHERE id = $2",
        )
        .bind(serde_json::json!({
            "verified_at": chrono::Utc::now(),
            "webhook_event": event_type,
        }))
        .bind(payment_attempt_id)
        .execute(&mut *tx)
        .await;
    }

    let _ = sqlx::query(
        "UPDATE orders
         SET status = 'paid', updated_at = now()
         WHERE id = $1",
    )
    .bind(order_id)
    .execute(&mut *tx)
    .await;

    let _ = sqlx::query(
        "UPDATE webhook_events
         SET processed_at = now()
         WHERE provider = $1 AND reference = $2",
    )
    .bind(PAYSTACK_WEBHOOK_PROVIDER)
    .bind(&reference)
    .execute(&mut *tx)
    .await;

    let _ = tx.commit().await;
    StatusCode::OK
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::header::HeaderValue;
    use axum::response::IntoResponse;
    use chrono::{DateTime, Utc};
    use sqlx::postgres::PgPoolOptions;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    #[test]
    fn verify_paystack_signature_accepts_valid_hmac() {
        let secret = "test_paystack_secret";
        let body = br#"{"event":"charge.success"}"#;

        let mut mac = HmacSha512::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(body);
        let signature_hex = hex::encode(mac.finalize().into_bytes());

        verify_paystack_signature(secret, body, &signature_hex).expect("signature should verify");
    }

    #[tokio::test]
    async fn paystack_webhook_processes_once_and_marks_order_paid() {
        let database_url = match std::env::var("DATABASE_URL") {
            Ok(v) => v,
            Err(_) => return, // Skip DB-backed tests when no database is configured.
        };

        let paystack_secret = "test_paystack_secret";
        unsafe {
            std::env::set_var("PAYSTACK_SECRET_KEY", paystack_secret);
            std::env::set_var("PAYSTACK_WEBHOOK_DISABLE_SDK_VERIFY", "1");
        }

        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect(&database_url)
            .await
            .expect("connect db");

        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .expect("run migrations");

        let customer_id = Uuid::new_v4();
        let customer_email = format!("customer+{}@example.com", customer_id);
        sqlx::query("INSERT INTO customers (id, email, password_hash) VALUES ($1, $2, $3)")
            .bind(customer_id)
            .bind(customer_email)
            .bind("dummy_hash")
            .execute(&pool)
            .await
            .expect("insert customer");

        let order_id = Uuid::new_v4();
        let amount_cents: i64 = 5_000;
        sqlx::query(
            "INSERT INTO orders (id, customer_id, status, currency, subtotal_cents, shipping_cents, tax_cents, total_cents, delivery_address)
             VALUES ($1, $2, 'payment_initialized', 'NGN', $3, 0, 0, $3, '{}'::jsonb)",
        )
        .bind(order_id)
        .bind(customer_id)
        .bind(amount_cents)
        .execute(&pool)
        .await
        .expect("insert order");

        let payment_attempt_id = Uuid::new_v4();
        let reference = format!("ps_ref_{}", Uuid::new_v4());
        sqlx::query(
            "INSERT INTO payment_attempts (id, order_id, provider, paystack_reference, amount_cents, currency, status, raw_payload)
             VALUES ($1, $2, 'paystack', $3, $4, 'NGN', 'initialized', $5)",
        )
        .bind(payment_attempt_id)
        .bind(order_id)
        .bind(&reference)
        .bind(amount_cents)
        .bind(serde_json::json!({
            "authorization_url": "https://example.com/auth",
            "access_code": "ACME"
        }))
        .execute(&pool)
        .await
        .expect("insert payment attempt");

        let state = AppState {
            pool: pool.clone(),
            jwt_secret: "test".to_string(),
            jwt_issuer: "test".to_string(),
            access_token_ttl_secs: 3600,
        };

        let payload = serde_json::json!({
            "event": "charge.success",
            "data": {
                "reference": reference.clone(),
                "amount": amount_cents
            }
        });

        let body_bytes = serde_json::to_vec(&payload).expect("to vec");
        let mut mac = HmacSha512::new_from_slice(paystack_secret.as_bytes()).unwrap();
        mac.update(&body_bytes);
        let signature_hex = hex::encode(mac.finalize().into_bytes());

        // Use an allowlisted IP so the handler proceeds.
        let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(52, 31, 139, 75)), 12345);

        let mut headers = HeaderMap::new();
        headers.insert(
            "x-paystack-signature",
            HeaderValue::from_str(&signature_hex).expect("header value"),
        );

        let resp1 = paystack_webhook(
            ConnectInfo(peer),
            Extension(state.clone()),
            headers.clone(),
            Body::from(body_bytes.clone()),
        )
        .await
        .into_response();
        assert_eq!(resp1.status(), StatusCode::OK);

        let payment_status_1: String =
            sqlx::query("SELECT status FROM payment_attempts WHERE id = $1")
                .bind(payment_attempt_id)
                .fetch_one(&pool)
                .await
                .expect("fetch payment status")
                .try_get("status")
                .expect("try_get status");

        let order_status_1: String = sqlx::query("SELECT status FROM orders WHERE id = $1")
            .bind(order_id)
            .fetch_one(&pool)
            .await
            .expect("fetch order status")
            .try_get("status")
            .expect("try_get status");

        let processed_at_1: DateTime<Utc> = sqlx::query(
            "SELECT processed_at
             FROM webhook_events
             WHERE provider = 'paystack' AND reference = $1",
        )
        .bind(&reference)
        .fetch_one(&pool)
        .await
        .expect("fetch processed_at")
        .try_get("processed_at")
        .expect("try_get processed_at");

        // Second call with the same payload/reference should be de-duplicated.
        let resp2 = paystack_webhook(
            ConnectInfo(peer),
            Extension(state),
            headers,
            Body::from(body_bytes),
        )
        .await
        .into_response();
        assert_eq!(resp2.status(), StatusCode::OK);

        let payment_status_2: String =
            sqlx::query("SELECT status FROM payment_attempts WHERE id = $1")
                .bind(payment_attempt_id)
                .fetch_one(&pool)
                .await
                .expect("fetch payment status")
                .try_get("status")
                .expect("try_get status");

        let order_status_2: String = sqlx::query("SELECT status FROM orders WHERE id = $1")
            .bind(order_id)
            .fetch_one(&pool)
            .await
            .expect("fetch order status")
            .try_get("status")
            .expect("try_get status");

        let processed_at_2: DateTime<Utc> = sqlx::query(
            "SELECT processed_at
             FROM webhook_events
             WHERE provider = 'paystack' AND reference = $1",
        )
        .bind(&reference)
        .fetch_one(&pool)
        .await
        .expect("fetch processed_at")
        .try_get("processed_at")
        .expect("try_get processed_at");

        assert_eq!(payment_status_1, "verified");
        assert_eq!(order_status_1, "paid");

        assert_eq!(payment_status_2, payment_status_1);
        assert_eq!(order_status_2, order_status_1);
        assert_eq!(
            processed_at_2, processed_at_1,
            "process-once should not reprocess"
        );
    }
}
