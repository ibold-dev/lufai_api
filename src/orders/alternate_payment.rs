//! Customer endpoints: confirm cash-on-delivery and start installment (non-Paystack).

use axum::{Json, Router, extract::Extension, http::HeaderMap, routing::post};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, IntoActiveModel, QueryFilter, Set, TransactionTrait,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    db::db_err_is_unique_violation,
    entity::{order_payment_flow_idempotency, orders as order_tbl},
    http::error::ApiError,
    http::validation::check_json_value_size,
    payments::methods as payment_methods,
    state::AppState,
};

use super::routes::{
    OrderResponse, authorize_or_forbid, idempotency_key, order_obj, require_customer,
};
use super::service::fetch_order_with_items;

pub fn routes() -> Router {
    Router::new()
        .route(
            "/orders/{order_id}/payment/cash-on-delivery/confirm",
            post(confirm_cash_on_delivery),
        )
        .route(
            "/orders/{order_id}/payment/installment/start",
            post(start_installment),
        )
}

const FLOW_COD: &str = "cod_confirm";
const FLOW_INSTALLMENT: &str = "installment_start";

const STATUS_AWAITING: &str = "awaiting_payment";
const STATUS_COD: &str = "cod_confirmed";
const STATUS_INSTALLMENT: &str = "installment_started";

#[derive(Debug, Deserialize, Serialize, utoipa::ToSchema)]
pub struct StartInstallmentRequest {
    /// Number of installments (including any down payment window if you model it separately).
    pub num_installments: i32,
    #[serde(default)]
    pub notes: Option<String>,
}

#[utoipa::path(
    post,
    path = "/v1/orders/{order_id}/payment/cash-on-delivery/confirm",
    params(
        ("Idempotency-Key" = String, Header, description = "Idempotency key for this confirmation")
    ),
    responses(
        (status = 200, body = OrderResponse),
        (status = 400, body = crate::http::error::ProblemDetails),
        (status = 401, body = crate::http::error::ProblemDetails),
        (status = 403, body = crate::http::error::ProblemDetails),
        (status = 404, body = crate::http::error::ProblemDetails),
        (status = 409, body = crate::http::error::ProblemDetails),
        (status = 500, body = crate::http::error::ProblemDetails)
    ),
    security(("bearerAuth" = []))
)]
pub(crate) async fn confirm_cash_on_delivery(
    headers: HeaderMap,
    Extension(state): Extension<AppState>,
    axum::extract::Path(order_id): axum::extract::Path<Uuid>,
) -> Result<Json<OrderResponse>, ApiError> {
    let (actor_sub, customer_id) = require_customer(&headers, &state).await?;
    let idem = idempotency_key(&headers)?;

    authorize_or_forbid(&actor_sub, &order_obj(order_id), "pay", &actor_sub).await?;

    let order_row = order_tbl::Entity::find_by_id(order_id)
        .filter(order_tbl::Column::CustomerId.eq(customer_id))
        .one(&state.db)
        .await?
        .ok_or_else(|| ApiError::not_found("order not found"))?;

    if !order_row
        .allowed_payment_methods
        .iter()
        .any(|m| m == payment_methods::CASH_ON_DELIVERY)
    {
        return Err(ApiError::bad_request(
            "cash on delivery is not allowed for this order",
        ));
    }

    if order_row.status == STATUS_COD {
        return Ok(Json(
            fetch_order_with_items(&state.db, customer_id, order_id).await?,
        ));
    }

    if order_row.status != STATUS_AWAITING {
        return Err(ApiError::conflict(
            "order is not awaiting a payment choice (e.g. Paystack already started)",
        ));
    }

    let now = chrono::Utc::now();
    let tx = state.db.begin().await?;

    let m = order_tbl::Entity::find_by_id(order_id)
        .one(&tx)
        .await?
        .ok_or_else(|| ApiError::not_found("order not found"))?;

    if m.status == STATUS_COD {
        tx.commit().await?;
        return Ok(Json(
            fetch_order_with_items(&state.db, customer_id, order_id).await?,
        ));
    }

    if m.status != STATUS_AWAITING {
        tx.rollback().await.ok();
        return Err(ApiError::conflict(
            "order is not awaiting a payment choice (e.g. Paystack already started)",
        ));
    }

    let mut active = m.into_active_model();
    active.status = Set(STATUS_COD.to_string());
    active.payment_channel = Set(Some(payment_methods::CASH_ON_DELIVERY.to_string()));
    active.updated_at = Set(now);
    active.update(&tx).await?;

    tx.commit().await?;

    let idem_am = order_payment_flow_idempotency::ActiveModel {
        id: Set(Uuid::new_v4()),
        order_id: Set(order_id),
        customer_id: Set(customer_id),
        flow_kind: Set(FLOW_COD.to_string()),
        idempotency_key: Set(idem),
        created_at: Set(now),
    };

    if let Err(e) = order_payment_flow_idempotency::Entity::insert(idem_am)
        .exec(&state.db)
        .await
    {
        if !db_err_is_unique_violation(&e) {
            return Err(ApiError::from(e));
        }
    }

    Ok(Json(
        fetch_order_with_items(&state.db, customer_id, order_id).await?,
    ))
}

#[utoipa::path(
    post,
    path = "/v1/orders/{order_id}/payment/installment/start",
    request_body = StartInstallmentRequest,
    params(
        ("Idempotency-Key" = String, Header, description = "Idempotency key for starting installment")
    ),
    responses(
        (status = 200, body = OrderResponse),
        (status = 400, body = crate::http::error::ProblemDetails),
        (status = 401, body = crate::http::error::ProblemDetails),
        (status = 403, body = crate::http::error::ProblemDetails),
        (status = 404, body = crate::http::error::ProblemDetails),
        (status = 409, body = crate::http::error::ProblemDetails),
        (status = 500, body = crate::http::error::ProblemDetails)
    ),
    security(("bearerAuth" = []))
)]
pub(crate) async fn start_installment(
    headers: HeaderMap,
    Extension(state): Extension<AppState>,
    axum::extract::Path(order_id): axum::extract::Path<Uuid>,
    Json(req): Json<StartInstallmentRequest>,
) -> Result<Json<OrderResponse>, ApiError> {
    let (actor_sub, customer_id) = require_customer(&headers, &state).await?;
    let idem = idempotency_key(&headers)?;

    authorize_or_forbid(&actor_sub, &order_obj(order_id), "pay", &actor_sub).await?;

    if req.num_installments < 2 || req.num_installments > 60 {
        return Err(ApiError::bad_request(
            "num_installments must be between 2 and 60",
        ));
    }

    let plan_json = serde_json::to_value(&req)
        .map_err(|e| ApiError::internal(format!("installment plan json: {e}")))?;
    check_json_value_size("installment_plan", &plan_json)?;

    let order_row = order_tbl::Entity::find_by_id(order_id)
        .filter(order_tbl::Column::CustomerId.eq(customer_id))
        .one(&state.db)
        .await?
        .ok_or_else(|| ApiError::not_found("order not found"))?;

    if !order_row
        .allowed_payment_methods
        .iter()
        .any(|m| m == payment_methods::INSTALLMENT)
    {
        return Err(ApiError::bad_request(
            "installment is not allowed for this order",
        ));
    }

    if order_row.status == STATUS_INSTALLMENT {
        return Ok(Json(
            fetch_order_with_items(&state.db, customer_id, order_id).await?,
        ));
    }

    if order_row.status != STATUS_AWAITING {
        return Err(ApiError::conflict(
            "order is not awaiting a payment choice (e.g. Paystack already started)",
        ));
    }

    let now = chrono::Utc::now();
    let tx = state.db.begin().await?;

    let m = order_tbl::Entity::find_by_id(order_id)
        .one(&tx)
        .await?
        .ok_or_else(|| ApiError::not_found("order not found"))?;

    if m.status == STATUS_INSTALLMENT {
        tx.commit().await?;
        return Ok(Json(
            fetch_order_with_items(&state.db, customer_id, order_id).await?,
        ));
    }

    if m.status != STATUS_AWAITING {
        tx.rollback().await.ok();
        return Err(ApiError::conflict(
            "order is not awaiting a payment choice (e.g. Paystack already started)",
        ));
    }

    let mut active = m.into_active_model();
    active.status = Set(STATUS_INSTALLMENT.to_string());
    active.payment_channel = Set(Some(payment_methods::INSTALLMENT.to_string()));
    active.installment_plan = Set(Some(plan_json.into()));
    active.updated_at = Set(now);
    active.update(&tx).await?;

    tx.commit().await?;

    let idem_am = order_payment_flow_idempotency::ActiveModel {
        id: Set(Uuid::new_v4()),
        order_id: Set(order_id),
        customer_id: Set(customer_id),
        flow_kind: Set(FLOW_INSTALLMENT.to_string()),
        idempotency_key: Set(idem),
        created_at: Set(now),
    };

    if let Err(e) = order_payment_flow_idempotency::Entity::insert(idem_am)
        .exec(&state.db)
        .await
    {
        if !db_err_is_unique_violation(&e) {
            return Err(ApiError::from(e));
        }
    }

    Ok(Json(
        fetch_order_with_items(&state.db, customer_id, order_id).await?,
    ))
}
