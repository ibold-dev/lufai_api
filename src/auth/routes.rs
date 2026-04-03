use axum::{
    extract::Extension,
    routing::post,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, Set};
use uuid::Uuid;

use crate::{
    auth::{jwt, password},
    db::db_err_is_unique_violation,
    entity::{admin, customer, seller},
    http::error::ApiError,
    state::AppState,
};

pub fn routes() -> Router {
    Router::new()
        .route("/customers/auth/register", post(customer_register))
        .route("/customers/auth/login", post(customer_login))
        .route("/sellers/auth/login", post(seller_login))
        .route("/admins/auth/login", post(admin_login))
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct EmailPasswordRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct AuthResponse {
    pub access_token: String,
    pub token_type: &'static str,
    pub expires_in: i64,
    pub subject: String,
}

fn validate_email(email: &str) -> Result<(), ApiError> {
    if email.trim().is_empty() {
        return Err(ApiError::bad_request("email is required"));
    }
    // Minimal format check (avoid over-rejecting valid local parts).
    if !email.contains('@') {
        return Err(ApiError::bad_request("invalid email"));
    }
    Ok(())
}

#[utoipa::path(
    post,
    path = "/v1/customers/auth/register",
    request_body = EmailPasswordRequest,
    responses(
        (status = 200, body = AuthResponse),
        (status = 400, body = crate::http::error::ProblemDetails),
        (status = 409, body = crate::http::error::ProblemDetails),
    )
)]
pub(crate) async fn customer_register(
    Extension(state): Extension<AppState>,
    Json(req): Json<EmailPasswordRequest>,
) -> Result<Json<AuthResponse>, ApiError> {
    validate_email(&req.email)?;

    let password_hash = password::hash_password(&req.password)?;
    let email = req.email.trim();

    let customer_id = Uuid::new_v4();
    let now = chrono::Utc::now();
    let active = customer::ActiveModel {
        id: Set(customer_id),
        email: Set(email.to_string()),
        password_hash: Set(password_hash),
        phone: Set(None),
        address: Set(None),
        created_at: Set(now),
        updated_at: Set(now),
    };

    match customer::Entity::insert(active).exec(&state.db).await {
        Ok(_) => {}
        Err(e) => {
            if db_err_is_unique_violation(&e) {
                return Err(ApiError::conflict("email already in use"));
            }
            return Err(ApiError::from(e));
        }
    }

    let subject = format!("customer:{customer_id}");
    let access_token = jwt::create_access_token(
        &subject,
        &state.jwt_secret,
        &state.jwt_issuer,
        state.access_token_ttl_secs,
    )?;

    Ok(Json(AuthResponse {
        access_token,
        token_type: "bearer",
        expires_in: state.access_token_ttl_secs,
        subject,
    }))
}

#[utoipa::path(
    post,
    path = "/v1/customers/auth/login",
    request_body = EmailPasswordRequest,
    responses(
        (status = 200, body = AuthResponse),
        (status = 400, body = crate::http::error::ProblemDetails),
        (status = 401, body = crate::http::error::ProblemDetails),
    )
)]
pub(crate) async fn customer_login(
    Extension(state): Extension<AppState>,
    Json(req): Json<EmailPasswordRequest>,
) -> Result<Json<AuthResponse>, ApiError> {
    validate_email(&req.email)?;
    let email = req.email.trim();

    let row = customer::Entity::find()
        .filter(customer::Column::Email.eq(email))
        .one(&state.db)
        .await?;

    let Some(row) = row else {
        return Err(ApiError::unauthorized());
    };

    let customer_id = row.id;
    let password_hash = row.password_hash;

    let ok = password::verify_password(&password_hash, &req.password)?;
    if !ok {
        return Err(ApiError::unauthorized());
    }

    let subject = format!("customer:{customer_id}");
    let access_token = jwt::create_access_token(
        &subject,
        &state.jwt_secret,
        &state.jwt_issuer,
        state.access_token_ttl_secs,
    )?;

    Ok(Json(AuthResponse {
        access_token,
        token_type: "bearer",
        expires_in: state.access_token_ttl_secs,
        subject,
    }))
}

#[utoipa::path(
    post,
    path = "/v1/sellers/auth/login",
    request_body = EmailPasswordRequest,
    responses(
        (status = 200, body = AuthResponse),
        (status = 400, body = crate::http::error::ProblemDetails),
        (status = 401, body = crate::http::error::ProblemDetails),
    )
)]
pub(crate) async fn seller_login(
    Extension(state): Extension<AppState>,
    Json(req): Json<EmailPasswordRequest>,
) -> Result<Json<AuthResponse>, ApiError> {
    validate_email(&req.email)?;
    let email = req.email.trim();

    let row = seller::Entity::find()
        .filter(seller::Column::Email.eq(email))
        .one(&state.db)
        .await?;

    let Some(row) = row else {
        return Err(ApiError::unauthorized());
    };

    let seller_id = row.id;
    let password_hash = row.password_hash;

    let ok = password::verify_password(&password_hash, &req.password)?;
    if !ok {
        return Err(ApiError::unauthorized());
    }

    let subject = format!("seller:{seller_id}");
    let access_token = jwt::create_access_token(
        &subject,
        &state.jwt_secret,
        &state.jwt_issuer,
        state.access_token_ttl_secs,
    )?;

    Ok(Json(AuthResponse {
        access_token,
        token_type: "bearer",
        expires_in: state.access_token_ttl_secs,
        subject,
    }))
}

#[utoipa::path(
    post,
    path = "/v1/admins/auth/login",
    request_body = EmailPasswordRequest,
    responses(
        (status = 200, body = AuthResponse),
        (status = 400, body = crate::http::error::ProblemDetails),
        (status = 401, body = crate::http::error::ProblemDetails),
    )
)]
pub(crate) async fn admin_login(
    Extension(state): Extension<AppState>,
    Json(req): Json<EmailPasswordRequest>,
) -> Result<Json<AuthResponse>, ApiError> {
    validate_email(&req.email)?;
    let email = req.email.trim();

    let row = admin::Entity::find()
        .filter(admin::Column::Email.eq(email))
        .one(&state.db)
        .await?;

    let Some(row) = row else {
        return Err(ApiError::unauthorized());
    };

    let admin_id = row.id;
    let password_hash = row.password_hash;

    let ok = password::verify_password(&password_hash, &req.password)?;
    if !ok {
        return Err(ApiError::unauthorized());
    }

    let subject = format!("admin:{admin_id}");
    let access_token = jwt::create_access_token(
        &subject,
        &state.jwt_secret,
        &state.jwt_issuer,
        state.access_token_ttl_secs,
    )?;

    Ok(Json(AuthResponse {
        access_token,
        token_type: "bearer",
        expires_in: state.access_token_ttl_secs,
        subject,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_email_rejects_empty() {
        let err = validate_email("").unwrap_err();
        match err {
            ApiError::BadRequest(_) => {}
            _ => panic!("expected BadRequest"),
        }
    }

    #[test]
    fn validate_email_rejects_without_at() {
        let err = validate_email("not-an-email").unwrap_err();
        match err {
            ApiError::BadRequest(_) => {}
            _ => panic!("expected BadRequest"),
        }
    }

    #[test]
    fn validate_email_accepts_basic_format() {
        validate_email("user@example.com").expect("should accept basic email format");
    }
}
