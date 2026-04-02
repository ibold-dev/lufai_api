use axum::{Json, Router, extract::Extension, http::HeaderMap, routing::post};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use sqlx::Row;
use uuid::Uuid;

use crate::{auth::jwt, authz::casbin as casbin_authz, http::error::ApiError, state::AppState};

use sha2::{Digest, Sha256};

pub fn routes() -> Router {
    Router::new()
        .route("/orders", post(create_order))
        .route("/orders/:order_id", axum::routing::get(get_order))
        .route(
            "/orders/:order_id/paystack/initialize",
            post(initialize_paystack),
        )
}

#[derive(Debug, Deserialize, Clone, utoipa::ToSchema)]
pub struct CreateOrderItemInput {
    pub product_id: Uuid,
    pub quantity: i32,
}

#[derive(Debug, Deserialize, Clone, utoipa::ToSchema)]
pub struct CreateOrderRequest {
    pub items: Vec<CreateOrderItemInput>,
    pub delivery_address: serde_json::Value,
    pub shipping_cents: Option<i64>,
    pub tax_cents: Option<i64>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct OrderItemResponse {
    pub product_id: Uuid,
    pub quantity: i32,
    pub unit_price_cents: i64,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct OrderResponse {
    pub id: Uuid,
    pub customer_id: Uuid,
    pub status: String,
    pub currency: String,
    pub subtotal_cents: i64,
    pub shipping_cents: i64,
    pub tax_cents: i64,
    pub total_cents: i64,
    pub delivery_address: serde_json::Value,
    pub items: Vec<OrderItemResponse>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct PaystackInitializeResponse {
    pub order_id: Uuid,
    pub paystack_reference: String,
    pub authorization_url: String,
    pub access_code: String,
}

fn bearer_token(headers: &HeaderMap) -> Result<String, ApiError> {
    let auth = headers
        .get("Authorization")
        .ok_or_else(ApiError::unauthorized)?;
    let auth = auth.to_str().map_err(|_| ApiError::unauthorized())?;

    let Some(token) = auth.strip_prefix("Bearer ") else {
        return Err(ApiError::unauthorized());
    };
    Ok(token.to_string())
}

fn principal_from_sub(sub: &str) -> Result<(String, Uuid), ApiError> {
    let (prefix, id_str) = sub
        .split_once(':')
        .ok_or_else(ApiError::unauthorized)?;
    let id = Uuid::parse_str(id_str).map_err(|_| ApiError::unauthorized())?;
    Ok((prefix.to_string(), id))
}

async fn require_customer(
    headers: &HeaderMap,
    state: &AppState,
) -> Result<(String, Uuid), ApiError> {
    let token = bearer_token(headers)?;
    let claims = jwt::decode_access_token(&token, &state.jwt_secret, &state.jwt_issuer)?;
    let sub = claims.sub;
    let (prefix, customer_id) = principal_from_sub(&sub)?;
    if prefix != "customer" {
        return Err(ApiError::forbidden());
    }
    Ok((sub, customer_id))
}

fn idempotency_key(headers: &HeaderMap) -> Result<String, ApiError> {
    let key = headers
        .get("Idempotency-Key")
        .ok_or_else(|| ApiError::bad_request("Idempotency-Key is required"))?;
    let key = key
        .to_str()
        .map_err(|_| ApiError::bad_request("bad Idempotency-Key"))?;
    if key.trim().is_empty() {
        return Err(ApiError::bad_request("Idempotency-Key must not be empty"));
    }
    Ok(key.to_string())
}

fn order_obj(order_id: Uuid) -> String {
    format!("/orders/{order_id}")
}

fn orders_collection_obj() -> String {
    "/orders/create".to_string()
}

async fn authorize_or_forbid(
    actor_sub: &str,
    obj: &str,
    act: &str,
    owner: &str,
) -> Result<(), ApiError> {
    let mut enforcer = casbin_authz::create_enforcer().await?;
    let allowed = casbin_authz::authorize_owned(&mut enforcer, actor_sub, obj, act, owner).await?;

    if !allowed {
        return Err(ApiError::forbidden());
    }
    Ok(())
}

async fn fetch_order_with_items(
    pool: &PgPool,
    customer_id: Uuid,
    order_id: Uuid,
) -> Result<OrderResponse, ApiError> {
    let order_row = sqlx::query(
        "SELECT id, customer_id, status, currency, subtotal_cents, shipping_cents, tax_cents, total_cents, delivery_address
         FROM orders WHERE id = $1 AND customer_id = $2",
    )
    .bind(order_id)
    .bind(customer_id)
    .fetch_optional(pool)
    .await?;

    let Some(order_row) = order_row else {
        return Err(ApiError::not_found("order not found"));
    };

    let items_rows = sqlx::query(
        "SELECT oi.product_id, oi.quantity, oi.unit_price_cents
         FROM order_items oi WHERE oi.order_id = $1 ORDER BY oi.created_at ASC",
    )
    .bind(order_id)
    .fetch_all(pool)
    .await?;

    let mut items = Vec::with_capacity(items_rows.len());
    for row in items_rows {
        items.push(OrderItemResponse {
            product_id: row.try_get("product_id")?,
            quantity: row.try_get("quantity")?,
            unit_price_cents: row.try_get("unit_price_cents")?,
        });
    }

    Ok(OrderResponse {
        id: order_row.try_get("id")?,
        customer_id: order_row.try_get("customer_id")?,
        status: order_row.try_get("status")?,
        currency: order_row.try_get("currency")?,
        subtotal_cents: order_row.try_get("subtotal_cents")?,
        shipping_cents: order_row.try_get("shipping_cents")?,
        tax_cents: order_row.try_get("tax_cents")?,
        total_cents: order_row.try_get("total_cents")?,
        delivery_address: order_row.try_get("delivery_address")?,
        items,
    })
}

#[utoipa::path(
    post,
    path = "/v1/orders",
    request_body = CreateOrderRequest,
    params(
        ("Idempotency-Key" = String, Header, description = "Idempotency key for order creation")
    ),
    responses(
        (status = 200, body = OrderResponse),
        (status = 400, body = crate::http::error::ProblemDetails),
        (status = 401, body = crate::http::error::ProblemDetails),
        (status = 403, body = crate::http::error::ProblemDetails),
        (status = 409, body = crate::http::error::ProblemDetails),
        (status = 500, body = crate::http::error::ProblemDetails)
    ),
    security(("bearerAuth" = []))
)]
pub(crate) async fn create_order(
    headers: HeaderMap,
    Extension(state): Extension<AppState>,
    Json(req): Json<CreateOrderRequest>,
) -> Result<Json<OrderResponse>, ApiError> {
    let (actor_sub, customer_id) = require_customer(&headers, &state).await?;
    let idemp_key = idempotency_key(&headers)?;

    if req.items.is_empty() {
        return Err(ApiError::bad_request("items must not be empty"));
    }

    let mut subtotal_cents: i64 = 0;
    let mut items_to_insert: Vec<(Uuid, i32, i64)> = Vec::with_capacity(req.items.len());

    for item in &req.items {
        if item.quantity <= 0 {
            return Err(ApiError::bad_request("quantity must be > 0"));
        }
        let row = sqlx::query(
            "SELECT id, price_cents FROM products WHERE id = $1 AND status = 'approved'",
        )
        .bind(item.product_id)
        .fetch_optional(&state.pool)
        .await?;

        let Some(row) = row else {
            return Err(ApiError::bad_request("product not available"));
        };

        let unit_price_cents: i64 = row.try_get("price_cents")?;
        subtotal_cents = subtotal_cents
            .checked_add(unit_price_cents.saturating_mul(item.quantity as i64))
            .ok_or_else(|| ApiError::bad_request("subtotal overflow"))?;

        items_to_insert.push((item.product_id, item.quantity, unit_price_cents));
    }

    let shipping_cents = req.shipping_cents.unwrap_or(0);
    let tax_cents = req.tax_cents.unwrap_or(0);
    if shipping_cents < 0 || tax_cents < 0 {
        return Err(ApiError::bad_request("shipping/tax must be >= 0"));
    }
    let total_cents = subtotal_cents + shipping_cents + tax_cents;

    // Authorization check for "create" orders (ownership self).
    authorize_or_forbid(&actor_sub, &orders_collection_obj(), "create", &actor_sub).await?;

    let mut tx = state.pool.begin().await?;

    // Idempotency hit?
    let existing = sqlx::query(
        "SELECT order_id
         FROM customer_order_idempotency
         WHERE customer_id = $1 AND idempotency_key = $2",
    )
    .bind(customer_id)
    .bind(&idemp_key)
    .fetch_optional(&mut *tx)
    .await?;

    if let Some(row) = existing {
        let order_id: Uuid = row.try_get("order_id")?;
        tx.rollback().await.ok();
        let order = fetch_order_with_items(&state.pool, customer_id, order_id).await?;
        return Ok(Json(order));
    }

    let insert_order = sqlx::query(
        "INSERT INTO orders (customer_id, status, currency, subtotal_cents, shipping_cents, tax_cents, total_cents, delivery_address)
         VALUES ($1, 'awaiting_payment', 'NGN', $2, $3, $4, $5, $6)
         RETURNING id, customer_id, status, currency, subtotal_cents, shipping_cents, tax_cents, total_cents, delivery_address",
    )
    .bind(customer_id)
    .bind(subtotal_cents)
    .bind(shipping_cents)
    .bind(tax_cents)
    .bind(total_cents)
    .bind(req.delivery_address)
    .fetch_one(&mut *tx)
    .await?;

    let order_id: Uuid = insert_order.try_get("id")?;

    for (product_id, quantity, unit_price_cents) in items_to_insert {
        sqlx::query(
            "INSERT INTO order_items (order_id, product_id, unit_price_cents, quantity)
             VALUES ($1, $2, $3, $4)",
        )
        .bind(order_id)
        .bind(product_id)
        .bind(unit_price_cents)
        .bind(quantity)
        .execute(&mut *tx)
        .await?;
    }

    // Store the idempotency key mapping.
    let mapping = sqlx::query(
        "INSERT INTO customer_order_idempotency (customer_id, idempotency_key, order_id)
         VALUES ($1, $2, $3)",
    )
    .bind(customer_id)
    .bind(&idemp_key)
    .bind(order_id)
    .execute(&mut *tx)
    .await;

    match mapping {
        Ok(_) => {
            tx.commit().await?;
        }
        Err(sqlx::Error::Database(db_err)) if db_err.code() == Some("23505".into()) => {
            // Concurrent identical request: rollback our inserts and return the existing order.
            tx.rollback().await.ok();
            let row = sqlx::query(
                "SELECT order_id FROM customer_order_idempotency
                 WHERE customer_id = $1 AND idempotency_key = $2",
            )
            .bind(customer_id)
            .bind(&idemp_key)
            .fetch_one(&state.pool)
            .await?;

            let existing_order_id: Uuid = row.try_get("order_id")?;
            let order = fetch_order_with_items(&state.pool, customer_id, existing_order_id).await?;
            return Ok(Json(order));
        }
        Err(err) => return Err(ApiError::from(err)),
    }

    let order = fetch_order_with_items(&state.pool, customer_id, order_id).await?;
    Ok(Json(order))
}

#[utoipa::path(
    get,
    path = "/v1/orders/{order_id}",
    responses(
        (status = 200, body = OrderResponse),
        (status = 401, body = crate::http::error::ProblemDetails),
        (status = 403, body = crate::http::error::ProblemDetails),
        (status = 404, body = crate::http::error::ProblemDetails),
        (status = 500, body = crate::http::error::ProblemDetails)
    ),
    security(("bearerAuth" = []))
)]
pub(crate) async fn get_order(
    headers: HeaderMap,
    Extension(state): Extension<AppState>,
    axum::extract::Path(order_id): axum::extract::Path<Uuid>,
) -> Result<Json<OrderResponse>, ApiError> {
    let (actor_sub, customer_id) = require_customer(&headers, &state).await?;

    // Ownership authorization.
    authorize_or_forbid(&actor_sub, &order_obj(order_id), "read", &actor_sub).await?;

    let order = fetch_order_with_items(&state.pool, customer_id, order_id).await?;
    Ok(Json(order))
}

fn deterministic_paystack_reference(order_id: Uuid, idempotency_key: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(order_id.to_string());
    hasher.update(b":");
    hasher.update(idempotency_key);
    let digest = hasher.finalize();

    // Paystack references are opaque strings; keep them reasonably short.
    let suffix = hex::encode(digest);
    format!("ord{}_{}", order_id, &suffix[..24])
}

async fn wait_for_payment_attempt(
    pool: &PgPool,
    payment_attempt_id: Uuid,
) -> Result<PaystackInitializeResponse, ApiError> {
    use tokio::time::{Duration, sleep};

    for _ in 0..20 {
        let row = sqlx::query(
            "SELECT status, raw_payload, paystack_reference, order_id
             FROM payment_attempts WHERE id = $1",
        )
        .bind(payment_attempt_id)
        .fetch_one(pool)
        .await?;

        let status: String = row.try_get("status")?;
        let paystack_reference: String = row.try_get("paystack_reference")?;
        let order_id: Uuid = row.try_get("order_id")?;

        if status == "initialized" {
            let raw_payload: Option<serde_json::Value> = row.try_get("raw_payload")?;
            let Some(raw_payload) = raw_payload else {
                return Err(ApiError::internal(
                    "missing raw_payload for initialized attempt".to_string(),
                ));
            };

            let authorization_url = raw_payload
                .get("authorization_url")
                .and_then(|v| v.as_str())
                .ok_or_else(|| ApiError::internal("missing authorization_url".to_string()))?;
            let access_code = raw_payload
                .get("access_code")
                .and_then(|v| v.as_str())
                .ok_or_else(|| ApiError::internal("missing access_code".to_string()))?;

            return Ok(PaystackInitializeResponse {
                order_id,
                paystack_reference,
                authorization_url: authorization_url.to_string(),
                access_code: access_code.to_string(),
            });
        }

        if status == "failed" {
            return Err(ApiError::internal(
                "paystack initialization failed".to_string(),
            ));
        }

        sleep(Duration::from_millis(250)).await;
    }

    Err(ApiError::conflict(
        "payment initialization is still processing, retry later",
    ))
}

#[utoipa::path(
    post,
    path = "/v1/orders/{order_id}/paystack/initialize",
    params(
        ("Idempotency-Key" = String, Header, description = "Idempotency key for payment initialization")
    ),
    responses(
        (status = 200, body = PaystackInitializeResponse),
        (status = 400, body = crate::http::error::ProblemDetails),
        (status = 401, body = crate::http::error::ProblemDetails),
        (status = 403, body = crate::http::error::ProblemDetails),
        (status = 404, body = crate::http::error::ProblemDetails),
        (status = 409, body = crate::http::error::ProblemDetails),
        (status = 500, body = crate::http::error::ProblemDetails)
    ),
    security(("bearerAuth" = []))
)]
pub(crate) async fn initialize_paystack(
    headers: HeaderMap,
    Extension(state): Extension<AppState>,
    axum::extract::Path(order_id): axum::extract::Path<Uuid>,
) -> Result<Json<PaystackInitializeResponse>, ApiError> {
    let (actor_sub, customer_id) = require_customer(&headers, &state).await?;
    let idemp_key = idempotency_key(&headers)?;

    authorize_or_forbid(&actor_sub, &order_obj(order_id), "pay", &actor_sub).await?;

    let order_row = sqlx::query(
        "SELECT o.total_cents, o.currency, c.email
             FROM orders o
             JOIN customers c ON c.id = o.customer_id
             WHERE o.id = $1 AND o.customer_id = $2",
    )
    .bind(order_id)
    .bind(customer_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| ApiError::not_found("order not found"))?;

    let order_total_cents: i64 = order_row.try_get("total_cents")?;
    let currency: String = order_row.try_get("currency")?;
    let customer_email: String = order_row.try_get("email")?;

    let reference = deterministic_paystack_reference(order_id, &idemp_key);

    // 1) Reserve or reuse the payment attempt for this idempotency key.
    let (payment_attempt_id, created_new_attempt) = {
        let mut tx = state.pool.begin().await?;

        if let Some(row) = sqlx::query(
            "SELECT payment_attempt_id
             FROM order_payment_idempotency
             WHERE order_id = $1 AND idempotency_key = $2",
        )
        .bind(order_id)
        .bind(&idemp_key)
        .fetch_optional(&mut *tx)
        .await?
        {
            tx.rollback().await.ok();
            (row.try_get::<Uuid, _>("payment_attempt_id")?, false)
        } else {
            // Create a pending payment attempt so other identical requests can wait.
            let payment_row = sqlx::query(
                "INSERT INTO payment_attempts
                 (order_id, provider, paystack_reference, amount_cents, currency, status, raw_payload)
                 VALUES ($1, 'paystack', $2, $3, $4, 'pending', NULL)
                 RETURNING id",
            )
            .bind(order_id)
            .bind(&reference)
            .bind(order_total_cents)
            .bind(&currency)
            .fetch_one(&mut *tx)
            .await?;

            let payment_attempt_id: Uuid = payment_row.try_get("id")?;

            let mapping = sqlx::query(
                "INSERT INTO order_payment_idempotency
                 (order_id, idempotency_key, payment_attempt_id)
                 VALUES ($1, $2, $3)",
            )
            .bind(order_id)
            .bind(&idemp_key)
            .bind(payment_attempt_id)
            .execute(&mut *tx)
            .await;

            match mapping {
                Ok(_) => {
                    tx.commit().await?;
                    (payment_attempt_id, true)
                }
                Err(sqlx::Error::Database(db_err)) if db_err.code() == Some("23505".into()) => {
                    tx.rollback().await.ok();
                    // Another concurrent identical request inserted the mapping.
                    let row = sqlx::query(
                        "SELECT payment_attempt_id
                         FROM order_payment_idempotency
                         WHERE order_id = $1 AND idempotency_key = $2",
                    )
                    .bind(order_id)
                    .bind(&idemp_key)
                    .fetch_one(&state.pool)
                    .await?;
                    (row.try_get("payment_attempt_id")?, false)
                }
                Err(err) => {
                    tx.rollback().await.ok();
                    return Err(ApiError::from(err));
                }
            }
        }
    };

    if !created_new_attempt {
        return Ok(Json(
            wait_for_payment_attempt(&state.pool, payment_attempt_id).await?,
        ));
    }

    // 2) Initialize the payment with Paystack.
    let paystack_secret = std::env::var("PAYSTACK_SECRET_KEY")
        .map_err(|_| ApiError::internal("PAYSTACK_SECRET_KEY missing".to_string()))?;
    let callback_url = std::env::var("PAYSTACK_CALLBACK_URL")
        .unwrap_or_else(|_| "https://example.com/paystack/callback".to_string());

    let client = reqwest::Client::new();
    let metadata = serde_json::json!({
        "order_id": order_id.to_string(),
        "customer_id": customer_id.to_string(),
        "idempotency_key": idemp_key,
    });

    let payload = serde_json::json!({
        "email": customer_email,
        "amount": order_total_cents,
        "currency": "NGN",
        "reference": reference,
        "callback_url": callback_url,
        "metadata": metadata,
    });

    let res = client
        .post("https://api.paystack.co/transaction/initialize")
        .bearer_auth(paystack_secret)
        .json(&payload)
        .send()
        .await
        .map_err(|e| ApiError::internal(format!("paystack request failed: {e}")))?;

    let body: serde_json::Value = res
        .json()
        .await
        .map_err(|e| ApiError::internal(format!("invalid paystack response: {e}")))?;

    if body.get("status").and_then(|v| v.as_bool()) != Some(true) {
        let message = body
            .get("message")
            .and_then(|v| v.as_str())
            .unwrap_or("paystack initialization failed");

        sqlx::query(
            "UPDATE payment_attempts
             SET status = 'failed', updated_at = now(), raw_payload = $1
             WHERE id = $2",
        )
        .bind(serde_json::json!({ "error": message }))
        .bind(payment_attempt_id)
        .execute(&state.pool)
        .await?;

        return Err(ApiError::bad_request(message));
    }

    let data = body
        .get("data")
        .ok_or_else(|| ApiError::internal("paystack missing data".to_string()))?;
    let authorization_url = data
        .get("authorization_url")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ApiError::internal("paystack missing authorization_url".to_string()))?;
    let access_code = data
        .get("access_code")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ApiError::internal("paystack missing access_code".to_string()))?;

    let raw_payload = serde_json::json!({
        "authorization_url": authorization_url,
        "access_code": access_code,
        "reference": reference,
    });

    // 3) Persist the initialized payment attempt + update order status.
    sqlx::query(
        "UPDATE payment_attempts
         SET status = 'initialized', updated_at = now(), raw_payload = $1
         WHERE id = $2",
    )
    .bind(&raw_payload)
    .bind(payment_attempt_id)
    .execute(&state.pool)
    .await?;

    sqlx::query(
        "UPDATE orders
         SET status = 'payment_initialized', updated_at = now()
         WHERE id = $1 AND customer_id = $2",
    )
    .bind(order_id)
    .bind(customer_id)
    .execute(&state.pool)
    .await?;

    Ok(Json(PaystackInitializeResponse {
        order_id,
        paystack_reference: reference,
        authorization_url: authorization_url.to_string(),
        access_code: access_code.to_string(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::header::HeaderValue;
    use sqlx::postgres::PgPoolOptions;
    use std::sync::OnceLock;
    use tokio::sync::Semaphore;

    // Prevent concurrent DB tests from stepping on each other in the same database.
    static DB_TEST_SEMAPHORE: OnceLock<Semaphore> = OnceLock::new();

    async fn test_pool() -> Option<sqlx::PgPool> {
        let database_url = std::env::var("DATABASE_URL").ok()?;
        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect(&database_url)
            .await
            .ok()?;

        sqlx::migrate!("./migrations").run(&pool).await.ok()?;
        Some(pool)
    }

    #[tokio::test]
    async fn create_order_is_idempotent_for_same_key() {
        let sem = DB_TEST_SEMAPHORE.get_or_init(|| Semaphore::new(1));
        let _permit = sem.acquire().await.expect("acquire semaphore permit");
        let pool = match test_pool().await {
            Some(p) => p,
            None => return, // Skip when DATABASE_URL is not set.
        };

        let jwt_secret = "test_jwt_secret";
        let jwt_issuer = "test_jwt_issuer";
        let customer_id = Uuid::new_v4();
        let seller_id = Uuid::new_v4();
        let product_id = Uuid::new_v4();

        sqlx::query(
            "INSERT INTO sellers (id, email, password_hash) VALUES ($1, $2, $3)",
        )
        .bind(seller_id)
        .bind(format!("seller+{}@example.com", Uuid::new_v4()))
        .bind("dummy_hash")
        .execute(&pool)
        .await
        .expect("insert seller");

        sqlx::query(
            "INSERT INTO products (id, seller_id, title, description, price_cents, currency, status)
             VALUES ($1, $2, $3, $4, $5, 'NGN', 'approved')",
        )
        .bind(product_id)
        .bind(seller_id)
        .bind("Chair")
        .bind("Wooden chair")
        .bind(2_500_i64)
        .execute(&pool)
        .await
        .expect("insert product");

        sqlx::query(
            "INSERT INTO customers (id, email, password_hash) VALUES ($1, $2, $3)",
        )
        .bind(customer_id)
        .bind(format!("customer+{}@example.com", Uuid::new_v4()))
        .bind("dummy_hash")
        .execute(&pool)
        .await
        .expect("insert customer");

        let state = AppState {
            pool: pool.clone(),
            jwt_secret: jwt_secret.to_string(),
            jwt_issuer: jwt_issuer.to_string(),
            access_token_ttl_secs: 3600,
        };

        let subject = format!("customer:{customer_id}");
        let access_token = jwt::create_access_token(
            &subject,
            &state.jwt_secret,
            &state.jwt_issuer,
            state.access_token_ttl_secs,
        )
        .expect("create token");

        let idempotency_key = format!("idem-create-{}", Uuid::new_v4());

        let req = CreateOrderRequest {
            items: vec![CreateOrderItemInput {
                product_id,
                quantity: 2,
            }],
            delivery_address: serde_json::json!({
                "street": "Main Road",
                "city": "Lagos"
            }),
            shipping_cents: None,
            tax_cents: None,
        };

        let mut headers = HeaderMap::new();
        headers.insert(
            "Authorization",
            HeaderValue::from_str(&format!("Bearer {access_token}"))
                .expect("header value"),
        );
        headers.insert(
            "Idempotency-Key",
            HeaderValue::from_str(&idempotency_key).expect("header value"),
        );

        let order_1 = create_order(
            headers.clone(),
            Extension(state.clone()),
            Json(req.clone()),
        )
        .await
        .expect("create order");

        let order_2 = create_order(
            headers,
            Extension(state),
            Json(req),
        )
        .await
        .expect("create order second time");

        assert_eq!(order_1.0.id, order_2.0.id, "idempotency should reuse order");

        let mapping_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM customer_order_idempotency
             WHERE customer_id = $1 AND idempotency_key = $2",
        )
        .bind(customer_id)
        .bind(&idempotency_key)
        .fetch_one(&pool)
        .await
        .expect("fetch mapping_count");

        assert_eq!(mapping_count, 1, "idempotency mapping should exist once");
    }

    #[tokio::test]
    async fn initialize_paystack_is_idempotent_for_same_key_without_network() {
        let sem = DB_TEST_SEMAPHORE.get_or_init(|| Semaphore::new(1));
        let _permit = sem.acquire().await.expect("acquire semaphore permit");
        let pool = match test_pool().await {
            Some(p) => p,
            None => return,
        };

        let jwt_secret = "test_jwt_secret";
        let jwt_issuer = "test_jwt_issuer";
        let customer_id = Uuid::new_v4();
        let seller_id = Uuid::new_v4();
        let product_id = Uuid::new_v4();
        let order_id = Uuid::new_v4();

        sqlx::query(
            "INSERT INTO sellers (id, email, password_hash) VALUES ($1, $2, $3)",
        )
        .bind(seller_id)
        .bind(format!("seller+{}@example.com", Uuid::new_v4()))
        .bind("dummy_hash")
        .execute(&pool)
        .await
        .expect("insert seller");

        sqlx::query(
            "INSERT INTO products (id, seller_id, title, description, price_cents, currency, status)
             VALUES ($1, $2, $3, $4, $5, 'NGN', 'approved')",
        )
        .bind(product_id)
        .bind(seller_id)
        .bind("Table")
        .bind("Oak table")
        .bind(3_000_i64)
        .execute(&pool)
        .await
        .expect("insert product");

        sqlx::query(
            "INSERT INTO customers (id, email, password_hash) VALUES ($1, $2, $3)",
        )
        .bind(customer_id)
        .bind(format!("customer+{}@example.com", Uuid::new_v4()))
        .bind("dummy_hash")
        .execute(&pool)
        .await
        .expect("insert customer");

        // Seed an order directly so we can pre-create the payment attempt without
        // calling the external Paystack API.
        let amount_cents: i64 = 3_000;
        sqlx::query(
            "INSERT INTO orders (id, customer_id, status, currency, subtotal_cents, shipping_cents, tax_cents, total_cents, delivery_address)
             VALUES ($1, $2, 'awaiting_payment', 'NGN', $3, 0, 0, $3, '{}'::jsonb)",
        )
        .bind(order_id)
        .bind(customer_id)
        .bind(amount_cents)
        .execute(&pool)
        .await
        .expect("insert order");

        let state = AppState {
            pool: pool.clone(),
            jwt_secret: jwt_secret.to_string(),
            jwt_issuer: jwt_issuer.to_string(),
            access_token_ttl_secs: 3600,
        };

        let subject = format!("customer:{customer_id}");
        let access_token = jwt::create_access_token(
            &subject,
            &state.jwt_secret,
            &state.jwt_issuer,
            state.access_token_ttl_secs,
        )
        .expect("create token");

        let idempotency_key = format!("idem-pay-{}", Uuid::new_v4());
        let paystack_reference = deterministic_paystack_reference(order_id, &idempotency_key);

        let payment_attempt_id = Uuid::new_v4();

        sqlx::query(
            "INSERT INTO payment_attempts (id, order_id, provider, paystack_reference, amount_cents, currency, status, raw_payload)
             VALUES ($1, $2, 'paystack', $3, $4, 'NGN', 'initialized', $5)",
        )
        .bind(payment_attempt_id)
        .bind(order_id)
        .bind(&paystack_reference)
        .bind(amount_cents)
        .bind(serde_json::json!({
            "authorization_url": "https://example.com/auth",
            "access_code": "ACME",
            "reference": paystack_reference.clone()
        }))
        .execute(&pool)
        .await
        .expect("insert payment_attempt");

        sqlx::query(
            "INSERT INTO order_payment_idempotency (order_id, idempotency_key, payment_attempt_id)
             VALUES ($1, $2, $3)",
        )
        .bind(order_id)
        .bind(&idempotency_key)
        .bind(payment_attempt_id)
        .execute(&pool)
        .await
        .expect("insert order_payment_idempotency");

        let mut headers = HeaderMap::new();
        headers.insert(
            "Authorization",
            HeaderValue::from_str(&format!("Bearer {access_token}"))
                .expect("header value"),
        );
        headers.insert(
            "Idempotency-Key",
            HeaderValue::from_str(&idempotency_key).expect("header value"),
        );

        let init_1 = initialize_paystack(
            headers.clone(),
            Extension(state.clone()),
            axum::extract::Path(order_id),
        )
        .await
        .expect("initialize paystack");

        let init_2 = initialize_paystack(
            headers,
            Extension(state),
            axum::extract::Path(order_id),
        )
        .await
        .expect("initialize paystack second time");

        assert_eq!(init_1.0.paystack_reference, init_2.0.paystack_reference);
        assert_eq!(init_1.0.access_code, init_2.0.access_code);
        assert_eq!(
            init_1.0.authorization_url,
            init_2.0.authorization_url,
        );

        let attempt_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM payment_attempts WHERE id = $1",
        )
        .bind(payment_attempt_id)
        .fetch_one(&pool)
        .await
        .expect("fetch payment_attempt count");

        assert_eq!(attempt_count, 1, "idempotency should not create duplicates");
    }
}
