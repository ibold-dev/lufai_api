use axum::{Router, routing::post};
use axum::{
    extract::{ConnectInfo, Extension},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use paystack::{PaystackClient, ReqwestClient};
use sea_orm::sea_query::OnConflict;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, IntoActiveModel, QueryFilter, QuerySelect, Set,
    TransactionTrait,
};
use serde_json::Value;
use sha2::Sha512;
use std::net::SocketAddr;
use uuid::Uuid;

use hmac::{Hmac, Mac};

use crate::{
    entity::{orders as order_tbl, payment_attempt, webhook_event},
    http::error::ApiError,
    http::limits::PAYSTACK_WEBHOOK_BODY_MAX,
    state::AppState,
};

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
    let res = client
        .transactions
        .verify_transaction(reference)
        .await
        .ok()?;
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

    let body_bytes = match axum::body::to_bytes(body, PAYSTACK_WEBHOOK_BODY_MAX).await {
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

    let tx = match state.db.begin().await {
        Ok(tx) => tx,
        Err(_) => return StatusCode::OK,
    };

    let rows = match webhook_event::Entity::insert(webhook_event::ActiveModel {
        id: Set(Uuid::new_v4()),
        provider: Set(PAYSTACK_WEBHOOK_PROVIDER.to_string()),
        event_type: Set(event_type.clone()),
        reference: Set(Some(reference.clone())),
        raw_payload: Set(payload.clone()),
        received_at: Set(chrono::Utc::now()),
        processed_at: Set(None),
    })
    .on_conflict(
        OnConflict::columns([
            webhook_event::Column::Provider,
            webhook_event::Column::Reference,
        ])
        .do_nothing()
        .to_owned(),
    )
    .exec_without_returning(&tx)
    .await
    {
        Ok(r) => r,
        Err(_) => {
            let _ = tx.commit().await;
            return StatusCode::OK;
        }
    };

    if rows == 0 {
        let _ = tx.commit().await;
        return StatusCode::OK;
    }

    let payment_row = match payment_attempt::Entity::find()
        .filter(payment_attempt::Column::PaystackReference.eq(&reference))
        .lock_exclusive()
        .one(&tx)
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

    let order_id = payment_row.order_id;
    let expected_amount = payment_row.amount_cents;
    let current_status = payment_row.status.clone();

    if amount_cents != expected_amount {
        let mut pa = payment_row.into_active_model();
        pa.status = Set("failed".to_string());
        pa.raw_payload = Set(Some(serde_json::json!({
            "error": "amount mismatch",
            "expected_amount": expected_amount,
            "verified_amount": amount_cents,
            "reference": reference,
        })));
        pa.updated_at = Set(chrono::Utc::now());
        let _ = pa.update(&tx).await;

        let _ = tx.commit().await;
        return StatusCode::OK;
    }

    if current_status != "verified" {
        let mut base: Value = payment_row
            .raw_payload
            .clone()
            .unwrap_or_else(|| serde_json::json!({}));
        if let Value::Object(ref mut m) = base {
            m.insert(
                "verified_at".to_string(),
                serde_json::json!(chrono::Utc::now()),
            );
            m.insert(
                "webhook_event".to_string(),
                serde_json::json!(event_type.clone()),
            );
        }
        let mut pa = payment_row.into_active_model();
        pa.status = Set("verified".to_string());
        pa.raw_payload = Set(Some(base));
        pa.updated_at = Set(chrono::Utc::now());
        let _ = pa.update(&tx).await;
    }

    if let Ok(Some(o)) = order_tbl::Entity::find_by_id(order_id).one(&tx).await {
        let mut oa = o.into_active_model();
        oa.status = Set("paid".to_string());
        oa.updated_at = Set(chrono::Utc::now());
        let _ = oa.update(&tx).await;
    }

    if let Ok(Some(ev)) = webhook_event::Entity::find()
        .filter(webhook_event::Column::Provider.eq(PAYSTACK_WEBHOOK_PROVIDER))
        .filter(webhook_event::Column::Reference.eq(reference.clone()))
        .one(&tx)
        .await
    {
        let mut eva = ev.into_active_model();
        eva.processed_at = Set(Some(chrono::Utc::now()));
        let _ = eva.update(&tx).await;
    }

    let _ = tx.commit().await;
    StatusCode::OK
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migration::Migrator;
    use axum::body::Body;
    use axum::http::header::HeaderValue;
    use axum::response::IntoResponse;
    use chrono::{DateTime, Utc};
    use sea_orm::{Set, SqlxPostgresConnector};
    use sea_orm_migration::MigratorTrait;
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
            Err(_) => return,
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

        let db = SqlxPostgresConnector::from_sqlx_postgres_pool(pool);
        Migrator::up(&db, None).await.expect("run migrations");

        let customer_id = Uuid::new_v4();
        let customer_email = format!("customer+{}@example.com", customer_id);
        let now = chrono::Utc::now();
        crate::entity::customer::Entity::insert(crate::entity::customer::ActiveModel {
            id: Set(customer_id),
            email: Set(customer_email),
            password_hash: Set(Some("dummy_hash".into())),
            google_sub: Set(None),
            full_name: Set("Test Customer".into()),
            affiliate_id: Set(None),
            phone: Set(None),
            address: Set(None),
            created_at: Set(now),
            updated_at: Set(now),
        })
        .exec(&db)
        .await
        .expect("insert customer");

        let order_id = Uuid::new_v4();
        let amount_cents: i64 = 5_000;
        crate::entity::orders::Entity::insert(crate::entity::orders::ActiveModel {
            id: Set(order_id),
            customer_id: Set(customer_id),
            status: Set("payment_initialized".into()),
            currency: Set("NGN".into()),
            subtotal_cents: Set(amount_cents),
            shipping_cents: Set(0),
            tax_cents: Set(0),
            total_cents: Set(amount_cents),
            allowed_payment_methods: Set(
                crate::payments::methods::vec_to_json_methods(
                    crate::payments::methods::all_payment_methods(),
                )
                .expect("methods json"),
            ),
            payment_channel: Set(None),
            installment_plan: Set(None),
            delivery_address: Set(serde_json::json!({})),
            created_at: Set(now),
            updated_at: Set(now),
        })
        .exec(&db)
        .await
        .expect("insert order");

        let payment_attempt_id = Uuid::new_v4();
        let reference = format!("ps_ref_{}", Uuid::new_v4());
        payment_attempt::Entity::insert(payment_attempt::ActiveModel {
            id: Set(payment_attempt_id),
            order_id: Set(order_id),
            provider: Set("paystack".into()),
            paystack_reference: Set(reference.clone()),
            amount_cents: Set(amount_cents),
            currency: Set("NGN".into()),
            status: Set("initialized".into()),
            raw_payload: Set(Some(serde_json::json!({
                "authorization_url": "https://example.com/auth",
                "access_code": "ACME"
            }))),
            paid_at: Set(None),
            created_at: Set(now),
            updated_at: Set(now),
        })
        .exec(&db)
        .await
        .expect("insert payment attempt");

        let state = AppState {
            db: db.clone(),
            jwt_secret: "test".to_string(),
            jwt_issuer: "test".to_string(),
            access_token_ttl_secs: 3600,
            http_client: reqwest::Client::new(),
            google_client_id: None,
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

        let payment_status_1: String = payment_attempt::Entity::find_by_id(payment_attempt_id)
            .one(&db)
            .await
            .expect("fetch payment")
            .expect("row")
            .status;

        let order_status_1: String = order_tbl::Entity::find_by_id(order_id)
            .one(&db)
            .await
            .expect("fetch order")
            .expect("row")
            .status;

        let processed_at_1: DateTime<Utc> = webhook_event::Entity::find()
            .filter(webhook_event::Column::Provider.eq("paystack"))
            .filter(webhook_event::Column::Reference.eq(Some(reference.clone())))
            .one(&db)
            .await
            .expect("fetch webhook")
            .expect("row")
            .processed_at
            .expect("processed_at");

        let resp2 = paystack_webhook(
            ConnectInfo(peer),
            Extension(state),
            headers,
            Body::from(body_bytes),
        )
        .await
        .into_response();
        assert_eq!(resp2.status(), StatusCode::OK);

        let payment_status_2: String = payment_attempt::Entity::find_by_id(payment_attempt_id)
            .one(&db)
            .await
            .expect("fetch payment")
            .expect("row")
            .status;

        let order_status_2: String = order_tbl::Entity::find_by_id(order_id)
            .one(&db)
            .await
            .expect("fetch order")
            .expect("row")
            .status;

        let processed_at_2: DateTime<Utc> = webhook_event::Entity::find()
            .filter(webhook_event::Column::Provider.eq("paystack"))
            .filter(webhook_event::Column::Reference.eq(Some(reference.clone())))
            .one(&db)
            .await
            .expect("fetch webhook")
            .expect("row")
            .processed_at
            .expect("processed_at");

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
