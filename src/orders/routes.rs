use axum::{Json, Router, extract::Extension, http::HeaderMap, routing::post};
use serde::{Deserialize, Serialize};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, IntoActiveModel, QueryFilter,
    QueryOrder, Set, TransactionTrait,
};
use uuid::Uuid;

use crate::{
    auth::jwt,
    authz::casbin as casbin_authz,
    db::db_err_is_unique_violation,
    entity::{
        customer, customer_order_idempotency, order_item, order_payment_idempotency,
        orders as order_tbl, payment_attempt, product,
    },
    http::error::ApiError,
    http::limits::{MAX_IDEMPOTENCY_KEY_LEN, MAX_LINE_ITEM_QUANTITY, MAX_ORDER_LINE_ITEMS},
    http::validation::check_json_value_size,
    state::AppState,
};

use paystack::{Currency, PaystackClient, ReqwestClient, TransactionRequestBuilder};
use sha2::{Digest, Sha256};

pub fn routes() -> Router {
    Router::new()
        .route("/orders", post(create_order))
        .route("/orders/{order_id}", axum::routing::get(get_order))
        .route(
            "/orders/{order_id}/paystack/initialize",
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
    if key.len() > MAX_IDEMPOTENCY_KEY_LEN {
        return Err(ApiError::bad_request("Idempotency-Key is too long"));
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
    db: &DatabaseConnection,
    customer_id: Uuid,
    order_id: Uuid,
) -> Result<OrderResponse, ApiError> {
    let order_row = order_tbl::Entity::find_by_id(order_id)
        .filter(order_tbl::Column::CustomerId.eq(customer_id))
        .one(db)
        .await?
        .ok_or_else(|| ApiError::not_found("order not found"))?;

    let items_rows = order_item::Entity::find()
        .filter(order_item::Column::OrderId.eq(order_id))
        .order_by_asc(order_item::Column::CreatedAt)
        .all(db)
        .await?;

    let items = items_rows
        .into_iter()
        .map(|r| OrderItemResponse {
            product_id: r.product_id,
            quantity: r.quantity,
            unit_price_cents: r.unit_price_cents,
        })
        .collect();

    Ok(OrderResponse {
        id: order_row.id,
        customer_id: order_row.customer_id,
        status: order_row.status,
        currency: order_row.currency,
        subtotal_cents: order_row.subtotal_cents,
        shipping_cents: order_row.shipping_cents,
        tax_cents: order_row.tax_cents,
        total_cents: order_row.total_cents,
        delivery_address: order_row.delivery_address,
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

    check_json_value_size("delivery_address", &req.delivery_address)?;

    if req.items.is_empty() {
        return Err(ApiError::bad_request("items must not be empty"));
    }
    if req.items.len() > MAX_ORDER_LINE_ITEMS {
        return Err(ApiError::bad_request("too many line items"));
    }

    let mut subtotal_cents: i64 = 0;
    let mut items_to_insert: Vec<(Uuid, i32, i64)> = Vec::with_capacity(req.items.len());

    for item in &req.items {
        if item.quantity <= 0 {
            return Err(ApiError::bad_request("quantity must be > 0"));
        }
        if item.quantity > MAX_LINE_ITEM_QUANTITY {
            return Err(ApiError::bad_request("quantity is too large"));
        }
        let p = product::Entity::find_by_id(item.product_id)
            .filter(product::Column::Status.eq("approved"))
            .one(&state.db)
            .await?
            .ok_or_else(|| ApiError::bad_request("product not available"))?;

        let unit_price_cents = p.price_cents;
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

    authorize_or_forbid(&actor_sub, &orders_collection_obj(), "create", &actor_sub).await?;

    let tx = state.db.begin().await?;

    let existing = customer_order_idempotency::Entity::find()
        .filter(customer_order_idempotency::Column::CustomerId.eq(customer_id))
        .filter(customer_order_idempotency::Column::IdempotencyKey.eq(&idemp_key))
        .one(&tx)
        .await?;

    if let Some(row) = existing {
        let order_id = row.order_id;
        tx.rollback().await.ok();
        let order = fetch_order_with_items(&state.db, customer_id, order_id).await?;
        return Ok(Json(order));
    }

    let order_id = Uuid::new_v4();
    let now = chrono::Utc::now();
    let order_am = order_tbl::ActiveModel {
        id: Set(order_id),
        customer_id: Set(customer_id),
        status: Set("awaiting_payment".to_string()),
        currency: Set("NGN".to_string()),
        subtotal_cents: Set(subtotal_cents),
        shipping_cents: Set(shipping_cents),
        tax_cents: Set(tax_cents),
        total_cents: Set(total_cents),
        delivery_address: Set(req.delivery_address.clone()),
        created_at: Set(now),
        updated_at: Set(now),
    };
    order_tbl::Entity::insert(order_am).exec(&tx).await?;

    for (product_id, quantity, unit_price_cents) in items_to_insert {
        let oi = order_item::ActiveModel {
            id: Set(Uuid::new_v4()),
            order_id: Set(order_id),
            product_id: Set(product_id),
            unit_price_cents: Set(unit_price_cents),
            quantity: Set(quantity),
            created_at: Set(now),
        };
        order_item::Entity::insert(oi).exec(&tx).await?;
    }

    let map_am = customer_order_idempotency::ActiveModel {
        id: Set(Uuid::new_v4()),
        customer_id: Set(customer_id),
        idempotency_key: Set(idemp_key.clone()),
        order_id: Set(order_id),
        created_at: Set(now),
    };

    match customer_order_idempotency::Entity::insert(map_am)
        .exec(&tx)
        .await
    {
        Ok(_) => {
            tx.commit().await?;
        }
        Err(e) if db_err_is_unique_violation(&e) => {
            tx.rollback().await.ok();
            let row = customer_order_idempotency::Entity::find()
                .filter(customer_order_idempotency::Column::CustomerId.eq(customer_id))
                .filter(customer_order_idempotency::Column::IdempotencyKey.eq(&idemp_key))
                .one(&state.db)
                .await?
                .ok_or_else(|| ApiError::internal("idempotency row missing after conflict".to_string()))?;
            let existing_order_id = row.order_id;
            let order = fetch_order_with_items(&state.db, customer_id, existing_order_id).await?;
            return Ok(Json(order));
        }
        Err(e) => return Err(ApiError::from(e)),
    }

    let order = fetch_order_with_items(&state.db, customer_id, order_id).await?;
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

    authorize_or_forbid(&actor_sub, &order_obj(order_id), "read", &actor_sub).await?;

    let order = fetch_order_with_items(&state.db, customer_id, order_id).await?;
    Ok(Json(order))
}

fn paystack_currency_code(code: &str) -> Result<Currency, ApiError> {
    match code {
        "NGN" => Ok(Currency::NGN),
        "GHS" => Ok(Currency::GHS),
        "USD" => Ok(Currency::USD),
        "ZAR" => Ok(Currency::ZAR),
        "KES" => Ok(Currency::KES),
        "XOF" => Ok(Currency::XOF),
        _ => Err(ApiError::bad_request(
            "unsupported currency for Paystack integration",
        )),
    }
}

fn deterministic_paystack_reference(order_id: Uuid, idempotency_key: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(order_id.to_string());
    hasher.update(b":");
    hasher.update(idempotency_key);
    let digest = hasher.finalize();

    let suffix = hex::encode(digest);
    format!("ord{}_{}", order_id, &suffix[..24])
}

async fn wait_for_payment_attempt(
    db: &DatabaseConnection,
    payment_attempt_id: Uuid,
) -> Result<PaystackInitializeResponse, ApiError> {
    use tokio::time::{Duration, sleep};

    for _ in 0..20 {
        let row = payment_attempt::Entity::find_by_id(payment_attempt_id)
            .one(db)
            .await?
            .ok_or_else(|| ApiError::internal("payment attempt missing".to_string()))?;

        let status = row.status;
        let paystack_reference = row.paystack_reference;
        let order_id = row.order_id;

        if status == "initialized" {
            let Some(raw_payload): Option<serde_json::Value> =
                row.raw_payload
            else {
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

    let order_row = order_tbl::Entity::find_by_id(order_id)
        .filter(order_tbl::Column::CustomerId.eq(customer_id))
        .one(&state.db)
        .await?
        .ok_or_else(|| ApiError::not_found("order not found"))?;

    let order_total_cents = order_row.total_cents;
    let currency = order_row.currency.clone();

    let cust = customer::Entity::find_by_id(order_row.customer_id)
        .one(&state.db)
        .await?
        .ok_or_else(|| ApiError::internal("customer missing".to_string()))?;
    let customer_email = cust.email;

    let reference = deterministic_paystack_reference(order_id, &idemp_key);

    let (payment_attempt_id, created_new_attempt) = {
        let tx = state.db.begin().await?;

        if let Some(row) = order_payment_idempotency::Entity::find()
            .filter(order_payment_idempotency::Column::OrderId.eq(order_id))
            .filter(order_payment_idempotency::Column::IdempotencyKey.eq(&idemp_key))
            .one(&tx)
            .await?
        {
            tx.rollback().await.ok();
            (row.payment_attempt_id, false)
        } else {
            let payment_attempt_id = Uuid::new_v4();
            let now = chrono::Utc::now();
            let pa = payment_attempt::ActiveModel {
                id: Set(payment_attempt_id),
                order_id: Set(order_id),
                provider: Set("paystack".to_string()),
                paystack_reference: Set(reference.clone()),
                amount_cents: Set(order_total_cents),
                currency: Set(currency.clone()),
                status: Set("pending".to_string()),
                raw_payload: Set(None),
                paid_at: Set(None),
                created_at: Set(now),
                updated_at: Set(now),
            };
            payment_attempt::Entity::insert(pa).exec(&tx).await?;

            let map_am = order_payment_idempotency::ActiveModel {
                id: Set(Uuid::new_v4()),
                order_id: Set(order_id),
                idempotency_key: Set(idemp_key.clone()),
                payment_attempt_id: Set(payment_attempt_id),
                created_at: Set(now),
            };

            match order_payment_idempotency::Entity::insert(map_am)
                .exec(&tx)
                .await
            {
                Ok(_) => {
                    tx.commit().await?;
                    (payment_attempt_id, true)
                }
                Err(e) if db_err_is_unique_violation(&e) => {
                    tx.rollback().await.ok();
                    let row = order_payment_idempotency::Entity::find()
                        .filter(order_payment_idempotency::Column::OrderId.eq(order_id))
                        .filter(order_payment_idempotency::Column::IdempotencyKey.eq(&idemp_key))
                        .one(&state.db)
                        .await?
                        .ok_or_else(|| {
                            ApiError::internal("order_payment idempotency missing".to_string())
                        })?;
                    (row.payment_attempt_id, false)
                }
                Err(e) => {
                    tx.rollback().await.ok();
                    return Err(ApiError::from(e));
                }
            }
        }
    };

    if !created_new_attempt {
        return Ok(Json(
            wait_for_payment_attempt(&state.db, payment_attempt_id).await?,
        ));
    }

    let paystack_secret = std::env::var("PAYSTACK_SECRET_KEY")
        .map_err(|_| ApiError::internal("PAYSTACK_SECRET_KEY missing".to_string()))?;
    let callback_url = std::env::var("PAYSTACK_CALLBACK_URL")
        .unwrap_or_else(|_| "https://example.com/paystack/callback".to_string());

    let pay_currency = paystack_currency_code(&currency)?;

    let metadata = serde_json::json!({
        "order_id": order_id.to_string(),
        "customer_id": customer_id.to_string(),
        "idempotency_key": idemp_key,
    });
    let metadata_str = serde_json::to_string(&metadata)
        .map_err(|e| ApiError::internal(format!("paystack metadata: {e}")))?;

    let body = TransactionRequestBuilder::default()
        .amount(order_total_cents.to_string())
        .email(customer_email)
        .currency(pay_currency)
        .reference(reference.clone())
        .callback_url(callback_url)
        .metadata(metadata_str)
        .build()
        .map_err(|e| ApiError::internal(format!("paystack request build: {e}")))?;

    let client = PaystackClient::<ReqwestClient>::new(paystack_secret);
    let res = client
        .transactions
        .initialize_transaction(body)
        .await
        .map_err(|e| ApiError::internal(format!("paystack request failed: {e}")))?;

    if !res.status {
        let message = res.message.clone();
        let mut pa: payment_attempt::ActiveModel = payment_attempt::Entity::find_by_id(payment_attempt_id)
            .one(&state.db)
            .await?
            .ok_or_else(|| ApiError::internal("payment attempt missing".to_string()))?
            .into_active_model();
        pa.status = Set("failed".to_string());
        pa.raw_payload = Set(Some(serde_json::json!({ "error": message })));
        pa.updated_at = Set(chrono::Utc::now());
        pa.update(&state.db).await?;

        return Err(ApiError::bad_request(message));
    }

    let data = res
        .data
        .ok_or_else(|| ApiError::internal("paystack missing data".to_string()))?;

    let raw_payload = serde_json::json!({
        "authorization_url": data.authorization_url,
        "access_code": data.access_code,
        "reference": reference,
    });

    let mut pa: payment_attempt::ActiveModel = payment_attempt::Entity::find_by_id(payment_attempt_id)
        .one(&state.db)
        .await?
        .ok_or_else(|| ApiError::internal("payment attempt missing".to_string()))?
        .into_active_model();
    pa.status = Set("initialized".to_string());
    pa.raw_payload = Set(Some(raw_payload));
    pa.updated_at = Set(chrono::Utc::now());
    pa.update(&state.db).await?;

    let mut ord: order_tbl::ActiveModel = order_tbl::Entity::find_by_id(order_id)
        .one(&state.db)
        .await?
        .ok_or_else(|| ApiError::not_found("order not found"))?
        .into_active_model();
    ord.status = Set("payment_initialized".to_string());
    ord.updated_at = Set(chrono::Utc::now());
    ord.update(&state.db).await?;

    Ok(Json(PaystackInitializeResponse {
        order_id,
        paystack_reference: reference,
        authorization_url: data.authorization_url,
        access_code: data.access_code,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::header::HeaderValue;
    use crate::entity::seller;
    use crate::migration::Migrator;
    use sea_orm::{PaginatorTrait, Set, SqlxPostgresConnector};
    use sea_orm_migration::MigratorTrait;
    use sqlx::postgres::PgPoolOptions;
    use std::sync::OnceLock;
    use tokio::sync::Semaphore;

    static DB_TEST_SEMAPHORE: OnceLock<Semaphore> = OnceLock::new();

    async fn test_db() -> Option<DatabaseConnection> {
        let database_url = std::env::var("DATABASE_URL").ok()?;
        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect(&database_url)
            .await
            .ok()?;

        let db = SqlxPostgresConnector::from_sqlx_postgres_pool(pool);
        Migrator::up(&db, None).await.ok()?;
        Some(db)
    }

    #[tokio::test]
    async fn create_order_is_idempotent_for_same_key() {
        let sem = DB_TEST_SEMAPHORE.get_or_init(|| Semaphore::new(1));
        let _permit = sem.acquire().await.expect("acquire semaphore permit");
        let db = match test_db().await {
            Some(d) => d,
            None => return,
        };

        let jwt_secret = "test_jwt_secret_minimum_32_bytes______";
        let jwt_issuer = "test_jwt_issuer";
        let customer_id = Uuid::new_v4();
        let seller_id = Uuid::new_v4();
        let product_id = Uuid::new_v4();

        let now = chrono::Utc::now();
        seller::Entity::insert(seller::ActiveModel {
            id: Set(seller_id),
            email: Set(format!("seller+{}@example.com", Uuid::new_v4())),
            full_name: Set("Test Seller".into()),
            password_hash: Set("dummy_hash".into()),
            created_at: Set(now),
            updated_at: Set(now),
        })
        .exec(&db)
        .await
        .expect("insert seller");

        product::Entity::insert(product::ActiveModel {
            id: Set(product_id),
            seller_id: Set(seller_id),
            title: Set("Chair".into()),
            description: Set("Wooden chair".into()),
            price_cents: Set(2_500),
            currency: Set("NGN".into()),
            dimensions: Set(None),
            status: Set("approved".into()),
            created_at: Set(now),
            updated_at: Set(now),
        })
        .exec(&db)
        .await
        .expect("insert product");

        customer::Entity::insert(customer::ActiveModel {
            id: Set(customer_id),
            email: Set(format!("customer+{}@example.com", Uuid::new_v4())),
            password_hash: Set(Some("dummy_hash".into())),
            google_sub: Set(None),
            full_name: Set("Test Customer".into()),
            phone: Set(None),
            address: Set(None),
            created_at: Set(now),
            updated_at: Set(now),
        })
        .exec(&db)
        .await
        .expect("insert customer");

        let state = AppState {
            db: db.clone(),
            jwt_secret: jwt_secret.to_string(),
            jwt_issuer: jwt_issuer.to_string(),
            access_token_ttl_secs: 3600,
            http_client: reqwest::Client::new(),
            google_client_id: None,
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

        let order_2 = create_order(headers, Extension(state), Json(req))
            .await
            .expect("create order second time");

        assert_eq!(order_1.0.id, order_2.0.id, "idempotency should reuse order");

        let mapping_count = customer_order_idempotency::Entity::find()
            .filter(customer_order_idempotency::Column::CustomerId.eq(customer_id))
            .filter(customer_order_idempotency::Column::IdempotencyKey.eq(&idempotency_key))
            .count(&db)
            .await
            .expect("count mapping");

        assert_eq!(mapping_count, 1, "idempotency mapping should exist once");
    }

    #[tokio::test]
    async fn initialize_paystack_is_idempotent_for_same_key_without_network() {
        let sem = DB_TEST_SEMAPHORE.get_or_init(|| Semaphore::new(1));
        let _permit = sem.acquire().await.expect("acquire semaphore permit");
        let db = match test_db().await {
            Some(d) => d,
            None => return,
        };

        let jwt_secret = "test_jwt_secret_minimum_32_bytes______";
        let jwt_issuer = "test_jwt_issuer";
        let customer_id = Uuid::new_v4();
        let seller_id = Uuid::new_v4();
        let product_id = Uuid::new_v4();
        let order_id = Uuid::new_v4();

        let now = chrono::Utc::now();
        seller::Entity::insert(seller::ActiveModel {
            id: Set(seller_id),
            email: Set(format!("seller+{}@example.com", Uuid::new_v4())),
            full_name: Set("Test Seller".into()),
            password_hash: Set("dummy_hash".into()),
            created_at: Set(now),
            updated_at: Set(now),
        })
        .exec(&db)
        .await
        .expect("insert seller");

        product::Entity::insert(product::ActiveModel {
            id: Set(product_id),
            seller_id: Set(seller_id),
            title: Set("Table".into()),
            description: Set("Oak table".into()),
            price_cents: Set(3_000),
            currency: Set("NGN".into()),
            dimensions: Set(None),
            status: Set("approved".into()),
            created_at: Set(now),
            updated_at: Set(now),
        })
        .exec(&db)
        .await
        .expect("insert product");

        customer::Entity::insert(customer::ActiveModel {
            id: Set(customer_id),
            email: Set(format!("customer+{}@example.com", Uuid::new_v4())),
            password_hash: Set(Some("dummy_hash".into())),
            google_sub: Set(None),
            full_name: Set("Test Customer".into()),
            phone: Set(None),
            address: Set(None),
            created_at: Set(now),
            updated_at: Set(now),
        })
        .exec(&db)
        .await
        .expect("insert customer");

        let amount_cents: i64 = 3_000;
        order_tbl::Entity::insert(order_tbl::ActiveModel {
            id: Set(order_id),
            customer_id: Set(customer_id),
            status: Set("awaiting_payment".into()),
            currency: Set("NGN".into()),
            subtotal_cents: Set(amount_cents),
            shipping_cents: Set(0),
            tax_cents: Set(0),
            total_cents: Set(amount_cents),
            delivery_address: Set(serde_json::json!({})),
            created_at: Set(now),
            updated_at: Set(now),
        })
        .exec(&db)
        .await
        .expect("insert order");

        let state = AppState {
            db: db.clone(),
            jwt_secret: jwt_secret.to_string(),
            jwt_issuer: jwt_issuer.to_string(),
            access_token_ttl_secs: 3600,
            http_client: reqwest::Client::new(),
            google_client_id: None,
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

        payment_attempt::Entity::insert(payment_attempt::ActiveModel {
            id: Set(payment_attempt_id),
            order_id: Set(order_id),
            provider: Set("paystack".into()),
            paystack_reference: Set(paystack_reference.clone()),
            amount_cents: Set(amount_cents),
            currency: Set("NGN".into()),
            status: Set("initialized".into()),
            raw_payload: Set(Some(
                serde_json::json!({
                    "authorization_url": "https://example.com/auth",
                    "access_code": "ACME",
                    "reference": paystack_reference.clone()
                }),
            )),
            paid_at: Set(None),
            created_at: Set(now),
            updated_at: Set(now),
        })
        .exec(&db)
        .await
        .expect("insert payment_attempt");

        order_payment_idempotency::Entity::insert(order_payment_idempotency::ActiveModel {
            id: Set(Uuid::new_v4()),
            order_id: Set(order_id),
            idempotency_key: Set(idempotency_key.clone()),
            payment_attempt_id: Set(payment_attempt_id),
            created_at: Set(now),
        })
        .exec(&db)
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

        let attempt_count = payment_attempt::Entity::find()
            .filter(payment_attempt::Column::Id.eq(payment_attempt_id))
            .count(&db)
            .await
            .expect("count payment_attempt");

        assert_eq!(attempt_count, 1, "idempotency should not create duplicates");
    }
}
