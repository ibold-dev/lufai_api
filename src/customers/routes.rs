use axum::{
    extract::Extension,
    http::HeaderMap,
    routing::{get, patch},
    Json, Router,
};
use sea_orm::{ActiveModelTrait, EntityTrait, IntoActiveModel, Set};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::{
    entity::customer,
    http::error::ApiError,
    http::limits::{MAX_CUSTOMER_FULL_NAME_LEN, MAX_CUSTOMER_PHONE_LEN},
    http::validation::check_optional_json_value_size,
    orders::routes::{authorize_or_forbid, require_customer},
    state::AppState,
};

pub fn routes() -> Router {
    Router::new()
        .route("/customers/me", get(get_customer_profile))
        .route("/customers/me", patch(update_customer_profile))
}

fn customers_me_obj() -> &'static str {
    "/customers/me"
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct CustomerProfileResponse {
    pub id: Uuid,
    pub email: String,
    pub full_name: String,
    pub phone: Option<String>,
    pub address: Option<Value>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct UpdateCustomerProfileRequest {
    pub full_name: Option<String>,
    pub phone: Option<String>,
    /// Omit to leave unchanged; JSON `null` clears the stored address.
    pub address: Option<Value>,
}

fn validate_update_profile(req: &UpdateCustomerProfileRequest) -> Result<(), ApiError> {
    if let Some(ref name) = req.full_name {
        let n = name.trim();
        if n.is_empty() {
            return Err(ApiError::bad_request("full_name must not be empty"));
        }
        if n.chars().count() > MAX_CUSTOMER_FULL_NAME_LEN {
            return Err(ApiError::bad_request("full_name is too long"));
        }
    }
    if let Some(ref phone) = req.phone {
        let p = phone.trim();
        if p.len() > MAX_CUSTOMER_PHONE_LEN {
            return Err(ApiError::bad_request("phone is too long"));
        }
    }
    check_optional_json_value_size("address", &req.address)?;
    Ok(())
}

#[utoipa::path(
    get,
    path = "/v1/customers/me",
    responses(
        (status = 200, body = CustomerProfileResponse),
        (status = 401, body = crate::http::error::ProblemDetails),
        (status = 403, body = crate::http::error::ProblemDetails),
        (status = 404, body = crate::http::error::ProblemDetails),
        (status = 500, body = crate::http::error::ProblemDetails)
    ),
    security(("bearerAuth" = []))
)]
pub(crate) async fn get_customer_profile(
    headers: HeaderMap,
    Extension(state): Extension<AppState>,
) -> Result<Json<CustomerProfileResponse>, ApiError> {
    let (actor_sub, customer_id) = require_customer(&headers, &state).await?;
    authorize_or_forbid(&actor_sub, customers_me_obj(), "read", &actor_sub).await?;

    let row = customer::Entity::find_by_id(customer_id)
        .one(&state.db)
        .await?
        .ok_or_else(|| ApiError::not_found("customer not found"))?;

    Ok(Json(CustomerProfileResponse {
        id: row.id,
        email: row.email,
        full_name: row.full_name,
        phone: row.phone,
        address: row.address.map(Into::into),
        created_at: row.created_at.into(),
        updated_at: row.updated_at.into(),
    }))
}

#[utoipa::path(
    patch,
    path = "/v1/customers/me",
    request_body = UpdateCustomerProfileRequest,
    responses(
        (status = 200, body = CustomerProfileResponse),
        (status = 400, body = crate::http::error::ProblemDetails),
        (status = 401, body = crate::http::error::ProblemDetails),
        (status = 403, body = crate::http::error::ProblemDetails),
        (status = 404, body = crate::http::error::ProblemDetails),
        (status = 500, body = crate::http::error::ProblemDetails)
    ),
    security(("bearerAuth" = []))
)]
pub(crate) async fn update_customer_profile(
    headers: HeaderMap,
    Extension(state): Extension<AppState>,
    Json(req): Json<UpdateCustomerProfileRequest>,
) -> Result<Json<CustomerProfileResponse>, ApiError> {
    let (actor_sub, customer_id) = require_customer(&headers, &state).await?;
    authorize_or_forbid(&actor_sub, customers_me_obj(), "update", &actor_sub).await?;

    validate_update_profile(&req)?;

    if req.full_name.is_none() && req.phone.is_none() && req.address.is_none() {
        return Err(ApiError::bad_request(
            "at least one of full_name, phone, address is required",
        ));
    }

    let existing = customer::Entity::find_by_id(customer_id)
        .one(&state.db)
        .await?
        .ok_or_else(|| ApiError::not_found("customer not found"))?;

    let now = chrono::Utc::now();
    let mut active: customer::ActiveModel = existing.into_active_model();
    if let Some(name) = req.full_name {
        active.full_name = Set(name.trim().to_string());
    }
    if let Some(phone) = req.phone {
        let p = phone.trim();
        active.phone = Set(if p.is_empty() { None } else { Some(p.to_string()) });
    }
    if let Some(addr) = req.address {
        if addr.is_null() {
            active.address = Set(None);
        } else {
            active.address = Set(Some(addr));
        }
    }
    active.updated_at = Set(now);

    let row = active.update(&state.db).await?;

    Ok(Json(CustomerProfileResponse {
        id: row.id,
        email: row.email,
        full_name: row.full_name,
        phone: row.phone,
        address: row.address.map(Into::into),
        created_at: row.created_at.into(),
        updated_at: row.updated_at.into(),
    }))
}
