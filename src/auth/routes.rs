use axum::{
    extract::Extension,
    routing::post,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use uuid::Uuid;

use crate::{
    auth::{jwt, password},
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

    let insert = sqlx::query(
        "INSERT INTO customers (email, password_hash) \
         VALUES ($1, $2) RETURNING id",
    )
    .bind(email)
    .bind(&password_hash)
    .fetch_one(&state.pool)
    .await;

    let customer_id = match insert {
        Ok(row) => row
            .try_get::<Uuid, _>("id")
            .map_err(|e| ApiError::internal(format!("bad insert row: {e}")))?,
        Err(err) => {
            let msg = format!("failed to create customer: {err}");
            // Postgres unique violation: 23505
            if let sqlx::Error::Database(db_err) = &err
                && db_err.code() == Some("23505".into())
            {
                return Err(ApiError::conflict("email already in use"));
            }
            return Err(ApiError::internal(msg));
        }
    };

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

    let row = sqlx::query("SELECT id, password_hash FROM customers WHERE email = $1")
        .bind(email)
        .fetch_optional(&state.pool)
        .await
        .map_err(|e| ApiError::internal(format!("db error: {e}")))?;

    let Some(row) = row else {
        return Err(ApiError::unauthorized());
    };

    let customer_id: Uuid = row.try_get("id")?;
    let password_hash: String = row.try_get("password_hash")?;

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

    let row = sqlx::query("SELECT id, password_hash FROM sellers WHERE email = $1")
        .bind(email)
        .fetch_optional(&state.pool)
        .await
        .map_err(|e| ApiError::internal(format!("db error: {e}")))?;

    let Some(row) = row else {
        return Err(ApiError::unauthorized());
    };

    let seller_id: Uuid = row.try_get("id")?;
    let password_hash: String = row.try_get("password_hash")?;

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

    let row = sqlx::query("SELECT id, password_hash FROM admins WHERE email = $1")
        .bind(email)
        .fetch_optional(&state.pool)
        .await
        .map_err(|e| ApiError::internal(format!("db error: {e}")))?;

    let Some(row) = row else {
        return Err(ApiError::unauthorized());
    };

    let admin_id: Uuid = row.try_get("id")?;
    let password_hash: String = row.try_get("password_hash")?;

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
