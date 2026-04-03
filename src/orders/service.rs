//! Shared order creation and loading (used by direct `POST /orders` and cart checkout).

use sea_orm::{
    ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, QueryOrder, Set, TransactionTrait,
};
use uuid::Uuid;

use crate::{
    authz::casbin as casbin_authz,
    db::db_err_is_unique_violation,
    entity::{
        cart, cart_item, customer_order_idempotency, order_item, orders as order_tbl, product,
    },
    http::error::ApiError,
    http::limits::{MAX_LINE_ITEM_QUANTITY, MAX_ORDER_LINE_ITEMS},
    http::validation::check_json_value_size,
    state::AppState,
};

use super::routes::{CreateOrderRequest, OrderItemResponse, OrderResponse};

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

fn orders_collection_obj() -> String {
    "/orders/create".to_string()
}

async fn clear_cart_items_tx(
    tx: &sea_orm::DatabaseTransaction,
    customer_id: Uuid,
) -> Result<(), ApiError> {
    let Some(cart_row) = cart::Entity::find()
        .filter(cart::Column::CustomerId.eq(customer_id))
        .one(tx)
        .await?
    else {
        return Ok(());
    };
    cart_item::Entity::delete_many()
        .filter(cart_item::Column::CartId.eq(cart_row.id))
        .exec(tx)
        .await?;
    Ok(())
}

pub async fn fetch_order_with_items(
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

/// Creates an order from the request body. If `clear_customer_cart` is true, empties the
/// customer's cart in the same transaction after a **new** order is committed (not on idempotent replay).
pub async fn create_order_from_request(
    state: &AppState,
    customer_id: Uuid,
    actor_sub: &str,
    idempotency_key: &str,
    req: &CreateOrderRequest,
    clear_customer_cart: bool,
) -> Result<OrderResponse, ApiError> {
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

    authorize_or_forbid(actor_sub, &orders_collection_obj(), "create", actor_sub).await?;

    let tx = state.db.begin().await?;

    let existing = customer_order_idempotency::Entity::find()
        .filter(customer_order_idempotency::Column::CustomerId.eq(customer_id))
        .filter(customer_order_idempotency::Column::IdempotencyKey.eq(idempotency_key))
        .one(&tx)
        .await?;

    if let Some(row) = existing {
        let order_id = row.order_id;
        tx.rollback().await.ok();
        return fetch_order_with_items(&state.db, customer_id, order_id).await;
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
        idempotency_key: Set(idempotency_key.to_string()),
        order_id: Set(order_id),
        created_at: Set(now),
    };

    match customer_order_idempotency::Entity::insert(map_am)
        .exec(&tx)
        .await
    {
        Ok(_) => {
            if clear_customer_cart {
                clear_cart_items_tx(&tx, customer_id).await?;
            }
            tx.commit().await?;
        }
        Err(e) if db_err_is_unique_violation(&e) => {
            tx.rollback().await.ok();
            let row = customer_order_idempotency::Entity::find()
                .filter(customer_order_idempotency::Column::CustomerId.eq(customer_id))
                .filter(customer_order_idempotency::Column::IdempotencyKey.eq(idempotency_key))
                .one(&state.db)
                .await?
                .ok_or_else(|| {
                    ApiError::internal("idempotency row missing after conflict".to_string())
                })?;
            let existing_order_id = row.order_id;
            return fetch_order_with_items(&state.db, customer_id, existing_order_id).await;
        }
        Err(e) => return Err(ApiError::from(e)),
    }

    fetch_order_with_items(&state.db, customer_id, order_id).await
}
