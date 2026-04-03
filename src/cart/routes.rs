use axum::{
    Json, Router,
    extract::Extension,
    http::HeaderMap,
    routing::{delete, get, post, put},
};
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter, Set};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    authz::casbin as casbin_authz,
    db::db_err_is_unique_violation,
    entity::{cart, cart_item, product},
    http::error::ApiError,
    http::limits::{MAX_LINE_ITEM_QUANTITY, MAX_ORDER_LINE_ITEMS},
    orders::routes::{CreateOrderItemInput, CreateOrderRequest, OrderResponse},
    orders::service,
    state::AppState,
};

pub fn routes() -> Router {
    Router::new()
        .route("/cart", get(get_cart))
        .route("/cart/items", put(put_cart_item))
        .route("/cart/items/{product_id}", delete(delete_cart_item))
        .route("/cart/checkout", post(checkout_cart))
}

fn cart_obj() -> &'static str {
    "/cart"
}

fn cart_checkout_obj() -> &'static str {
    "/cart/checkout"
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

/// Ensures a row exists in `carts` for this customer (lazy creation).
async fn ensure_cart(
    db: &sea_orm::DatabaseConnection,
    customer_id: Uuid,
) -> Result<cart::Model, ApiError> {
    if let Some(row) = cart::Entity::find()
        .filter(cart::Column::CustomerId.eq(customer_id))
        .one(db)
        .await?
    {
        return Ok(row);
    }
    let id = Uuid::new_v4();
    let now = chrono::Utc::now();
    let am = cart::ActiveModel {
        id: Set(id),
        customer_id: Set(customer_id),
        created_at: Set(now),
        updated_at: Set(now),
    };
    match cart::Entity::insert(am).exec(db).await {
        Ok(_) => cart::Entity::find_by_id(id)
            .one(db)
            .await?
            .ok_or_else(|| ApiError::internal("cart insert missing row".to_string())),
        Err(e) if db_err_is_unique_violation(&e) => cart::Entity::find()
            .filter(cart::Column::CustomerId.eq(customer_id))
            .one(db)
            .await?
            .ok_or_else(|| ApiError::internal("cart missing after race".to_string())),
        Err(e) => Err(ApiError::from(e)),
    }
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct CartLineResponse {
    pub product_id: Uuid,
    pub quantity: i32,
    pub title: String,
    pub price_cents: i64,
    pub currency: String,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct CartResponse {
    pub items: Vec<CartLineResponse>,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct PutCartItemRequest {
    pub product_id: Uuid,
    /// Set to `0` to remove the line.
    pub quantity: i32,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct CartCheckoutRequest {
    pub delivery_address: serde_json::Value,
    pub shipping_cents: Option<i64>,
    pub tax_cents: Option<i64>,
}

#[utoipa::path(
    get,
    path = "/v1/cart",
    responses(
        (status = 200, body = CartResponse),
        (status = 401, body = crate::http::error::ProblemDetails),
        (status = 403, body = crate::http::error::ProblemDetails),
        (status = 500, body = crate::http::error::ProblemDetails)
    ),
    security(("bearerAuth" = []))
)]
pub(crate) async fn get_cart(
    headers: HeaderMap,
    Extension(state): Extension<AppState>,
) -> Result<Json<CartResponse>, ApiError> {
    let (actor_sub, customer_id) = crate::orders::routes::require_customer(&headers, &state).await?;
    authorize_or_forbid(&actor_sub, cart_obj(), "read", &actor_sub).await?;

    let cart_row = ensure_cart(&state.db, customer_id).await?;
    let lines = cart_item::Entity::find()
        .filter(cart_item::Column::CartId.eq(cart_row.id))
        .all(&state.db)
        .await?;

    let mut items = Vec::with_capacity(lines.len());
    for line in lines {
        let p = product::Entity::find_by_id(line.product_id)
            .one(&state.db)
            .await?
            .ok_or_else(|| ApiError::internal("cart references missing product".to_string()))?;
        items.push(CartLineResponse {
            product_id: line.product_id,
            quantity: line.quantity,
            title: p.title,
            price_cents: p.price_cents,
            currency: p.currency,
        });
    }

    Ok(Json(CartResponse { items }))
}

#[utoipa::path(
    put,
    path = "/v1/cart/items",
    request_body = PutCartItemRequest,
    responses(
        (status = 200, body = CartResponse),
        (status = 400, body = crate::http::error::ProblemDetails),
        (status = 401, body = crate::http::error::ProblemDetails),
        (status = 403, body = crate::http::error::ProblemDetails),
        (status = 500, body = crate::http::error::ProblemDetails)
    ),
    security(("bearerAuth" = []))
)]
pub(crate) async fn put_cart_item(
    headers: HeaderMap,
    Extension(state): Extension<AppState>,
    Json(req): Json<PutCartItemRequest>,
) -> Result<Json<CartResponse>, ApiError> {
    let (actor_sub, customer_id) = crate::orders::routes::require_customer(&headers, &state).await?;
    authorize_or_forbid(&actor_sub, "/cart/items", "update", &actor_sub).await?;

    if req.quantity < 0 {
        return Err(ApiError::bad_request("quantity must be >= 0"));
    }
    if req.quantity > MAX_LINE_ITEM_QUANTITY {
        return Err(ApiError::bad_request("quantity is too large"));
    }

    let cart_row = ensure_cart(&state.db, customer_id).await?;
    let now = chrono::Utc::now();

    if req.quantity == 0 {
        cart_item::Entity::delete_many()
            .filter(cart_item::Column::CartId.eq(cart_row.id))
            .filter(cart_item::Column::ProductId.eq(req.product_id))
            .exec(&state.db)
            .await?;
        let mut active: cart::ActiveModel = cart_row.into();
        active.updated_at = Set(now);
        active.update(&state.db).await?;
        return get_cart(headers, Extension(state.clone())).await;
    }

    product::Entity::find_by_id(req.product_id)
        .filter(product::Column::Status.eq("approved"))
        .one(&state.db)
        .await?
        .ok_or_else(|| ApiError::bad_request("product not available"))?;

    let existing = cart_item::Entity::find()
        .filter(cart_item::Column::CartId.eq(cart_row.id))
        .filter(cart_item::Column::ProductId.eq(req.product_id))
        .one(&state.db)
        .await?;

    let line_count = cart_item::Entity::find()
        .filter(cart_item::Column::CartId.eq(cart_row.id))
        .count(&state.db)
        .await?;

    if existing.is_none() && line_count >= MAX_ORDER_LINE_ITEMS as u64 {
        return Err(ApiError::bad_request("cart has too many distinct products"));
    }

    match existing {
        Some(row) => {
            let mut am: cart_item::ActiveModel = row.into();
            am.quantity = Set(req.quantity);
            am.update(&state.db).await?;
        }
        None => {
            cart_item::Entity::insert(cart_item::ActiveModel {
                id: Set(Uuid::new_v4()),
                cart_id: Set(cart_row.id),
                product_id: Set(req.product_id),
                quantity: Set(req.quantity),
            })
            .exec(&state.db)
            .await?;
        }
    }

    let mut active: cart::ActiveModel = cart::Entity::find_by_id(cart_row.id)
        .one(&state.db)
        .await?
        .ok_or_else(|| ApiError::not_found("cart"))?
        .into();
    active.updated_at = Set(now);
    active.update(&state.db).await?;

    get_cart(headers, Extension(state.clone())).await
}

#[utoipa::path(
    delete,
    path = "/v1/cart/items/{product_id}",
    responses(
        (status = 200, body = CartResponse),
        (status = 401, body = crate::http::error::ProblemDetails),
        (status = 403, body = crate::http::error::ProblemDetails),
        (status = 500, body = crate::http::error::ProblemDetails)
    ),
    security(("bearerAuth" = []))
)]
pub(crate) async fn delete_cart_item(
    headers: HeaderMap,
    Extension(state): Extension<AppState>,
    axum::extract::Path(product_id): axum::extract::Path<Uuid>,
) -> Result<Json<CartResponse>, ApiError> {
    let (actor_sub, customer_id) = crate::orders::routes::require_customer(&headers, &state).await?;
    authorize_or_forbid(&actor_sub, "/cart/items/*", "update", &actor_sub).await?;

    let cart_row = ensure_cart(&state.db, customer_id).await?;
    cart_item::Entity::delete_many()
        .filter(cart_item::Column::CartId.eq(cart_row.id))
        .filter(cart_item::Column::ProductId.eq(product_id))
        .exec(&state.db)
        .await?;
    let now = chrono::Utc::now();
    let mut active: cart::ActiveModel = cart::Entity::find_by_id(cart_row.id)
        .one(&state.db)
        .await?
        .ok_or_else(|| ApiError::not_found("cart"))?
        .into();
    active.updated_at = Set(now);
    active.update(&state.db).await?;

    get_cart(headers, Extension(state.clone())).await
}

#[utoipa::path(
    post,
    path = "/v1/cart/checkout",
    request_body = CartCheckoutRequest,
    params(
        ("Idempotency-Key" = String, Header, description = "Idempotency key for order creation")
    ),
    responses(
        (status = 200, body = OrderResponse),
        (status = 400, body = crate::http::error::ProblemDetails),
        (status = 401, body = crate::http::error::ProblemDetails),
        (status = 403, body = crate::http::error::ProblemDetails),
        (status = 500, body = crate::http::error::ProblemDetails)
    ),
    security(("bearerAuth" = []))
)]
pub(crate) async fn checkout_cart(
    headers: HeaderMap,
    Extension(state): Extension<AppState>,
    Json(body): Json<CartCheckoutRequest>,
) -> Result<Json<OrderResponse>, ApiError> {
    let (actor_sub, customer_id) = crate::orders::routes::require_customer(&headers, &state).await?;
    authorize_or_forbid(&actor_sub, cart_checkout_obj(), "create", &actor_sub).await?;
    let idemp_key = crate::orders::routes::idempotency_key(&headers)?;

    let cart_row = ensure_cart(&state.db, customer_id).await?;
    let lines = cart_item::Entity::find()
        .filter(cart_item::Column::CartId.eq(cart_row.id))
        .all(&state.db)
        .await?;

    if lines.is_empty() {
        return Err(ApiError::bad_request("cart is empty"));
    }

    let mut items: Vec<CreateOrderItemInput> = Vec::with_capacity(lines.len());
    for line in &lines {
        product::Entity::find_by_id(line.product_id)
            .filter(product::Column::Status.eq("approved"))
            .one(&state.db)
            .await?
            .ok_or_else(|| ApiError::bad_request("a product in your cart is no longer available"))?;
        items.push(CreateOrderItemInput {
            product_id: line.product_id,
            quantity: line.quantity,
        });
    }

    let req = CreateOrderRequest {
        items,
        delivery_address: body.delivery_address,
        shipping_cents: body.shipping_cents,
        tax_cents: body.tax_cents,
    };

    let order = service::create_order_from_request(
        &state,
        customer_id,
        &actor_sub,
        &idemp_key,
        &req,
        true,
    )
    .await?;
    Ok(Json(order))
}
