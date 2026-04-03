use axum::{
    extract::Extension,
    routing::post,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, IntoActiveModel, QueryFilter, Set};
use uuid::Uuid;
use validator::Validate;

use crate::{
    auth::{google, jwt, password},
    db::db_err_is_unique_violation,
    entity::{admin, customer, seller},
    http::error::ApiError,
    state::AppState,
};

pub fn routes() -> Router {
    Router::new()
        .route("/customers/auth/register", post(customer_register))
        .route("/customers/auth/login", post(customer_login))
        .route("/customers/auth/google", post(customer_google_sign_in))
        .route("/sellers/auth/login", post(seller_login))
        .route("/admins/auth/login", post(admin_login))
}

#[derive(Debug, Deserialize, Validate, utoipa::ToSchema)]
pub struct EmailPasswordRequest {
    #[validate(email, length(max = 254))]
    pub email: String,
    #[validate(length(min = 8, max = 256))]
    pub password: String,
}

#[derive(Debug, Deserialize, Validate, utoipa::ToSchema)]
pub struct CustomerRegisterRequest {
    #[validate(email, length(max = 254))]
    pub email: String,
    #[validate(length(min = 8, max = 256))]
    pub password: String,
    #[validate(length(min = 1, max = 200))]
    pub full_name: String,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct AuthResponse {
    pub access_token: String,
    pub token_type: &'static str,
    pub expires_in: i64,
    pub subject: String,
}

/// Google Sign-In ID token (from GIS / OAuth). Accepts JSON field `id_token` or `credential` (One Tap).
#[derive(Debug, Deserialize, Validate, utoipa::ToSchema)]
pub struct GoogleSignInRequest {
    #[validate(length(min = 10, max = 12000))]
    #[serde(alias = "credential")]
    pub id_token: String,
}

fn issue_customer_token(state: &AppState, customer_id: Uuid) -> Result<Json<AuthResponse>, ApiError> {
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

fn validate_credentials(req: &EmailPasswordRequest) -> Result<(), ApiError> {
    req.validate()
        .map_err(|_| ApiError::bad_request("invalid email or password"))
}

fn validate_customer_register(req: &CustomerRegisterRequest) -> Result<(), ApiError> {
    req.validate()
        .map_err(|_| ApiError::bad_request("invalid registration data"))
}

#[utoipa::path(
    post,
    path = "/v1/customers/auth/register",
    request_body = CustomerRegisterRequest,
    responses(
        (status = 200, body = AuthResponse),
        (status = 400, body = crate::http::error::ProblemDetails),
        (status = 409, body = crate::http::error::ProblemDetails),
    )
)]
pub(crate) async fn customer_register(
    Extension(state): Extension<AppState>,
    Json(req): Json<CustomerRegisterRequest>,
) -> Result<Json<AuthResponse>, ApiError> {
    validate_customer_register(&req)?;

    let password_hash = password::hash_password(&req.password)?;
    let email = req.email.trim().to_lowercase();
    let full_name = req.full_name.trim().to_string();

    let customer_id = Uuid::new_v4();
    let now = chrono::Utc::now();
    let active = customer::ActiveModel {
        id: Set(customer_id),
        email: Set(email),
        password_hash: Set(Some(password_hash)),
        google_sub: Set(None),
        full_name: Set(full_name),
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

    issue_customer_token(&state, customer_id)
}

#[utoipa::path(
    post,
    path = "/v1/customers/auth/google",
    request_body = GoogleSignInRequest,
    responses(
        (status = 200, body = AuthResponse),
        (status = 400, body = crate::http::error::ProblemDetails),
        (status = 409, body = crate::http::error::ProblemDetails),
        (status = 500, body = crate::http::error::ProblemDetails),
    )
)]
pub(crate) async fn customer_google_sign_in(
    Extension(state): Extension<AppState>,
    Json(req): Json<GoogleSignInRequest>,
) -> Result<Json<AuthResponse>, ApiError> {
    req.validate()
        .map_err(|_| ApiError::bad_request("invalid request"))?;
    let google_client_id = state.google_client_id.as_ref().ok_or_else(|| {
        ApiError::internal("Google sign-in is not configured (set GOOGLE_CLIENT_ID)".to_string())
    })?;

    let claims = google::verify_google_id_token(
        &state.http_client,
        google_client_id,
        &req.id_token,
    )
    .await?;

    let google_full_name = google::google_display_name(&claims);
    let email = claims.email.trim().to_lowercase();

    if let Some(row) = customer::Entity::find()
        .filter(customer::Column::GoogleSub.eq(claims.sub.as_str()))
        .one(&state.db)
        .await?
    {
        return issue_customer_token(&state, row.id);
    }

    if let Some(row) = customer::Entity::find()
        .filter(customer::Column::Email.eq(&email))
        .one(&state.db)
        .await?
    {
        if let Some(ref gs) = row.google_sub {
            if gs != &claims.sub {
                return Err(ApiError::conflict(
                    "email is already linked to a different Google account",
                ));
            }
            return issue_customer_token(&state, row.id);
        }
        let cid = row.id;
        let fill_name = row.full_name.trim().is_empty() && !google_full_name.is_empty();
        let sub = claims.sub;
        let mut active = row.into_active_model();
        active.google_sub = Set(Some(sub));
        if fill_name {
            active.full_name = Set(google_full_name);
        }
        active.updated_at = Set(chrono::Utc::now());
        active.update(&state.db).await?;
        return issue_customer_token(&state, cid);
    }

    let customer_id = Uuid::new_v4();
    let now = chrono::Utc::now();
    customer::Entity::insert(customer::ActiveModel {
        id: Set(customer_id),
        email: Set(email),
        password_hash: Set(None),
        google_sub: Set(Some(claims.sub)),
        full_name: Set(google_full_name),
        phone: Set(None),
        address: Set(None),
        created_at: Set(now),
        updated_at: Set(now),
    })
    .exec(&state.db)
    .await
    .map_err(|e| {
        if db_err_is_unique_violation(&e) {
            ApiError::conflict("could not create account")
        } else {
            ApiError::from(e)
        }
    })?;

    issue_customer_token(&state, customer_id)
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
    validate_credentials(&req)?;
    let email = req.email.trim().to_lowercase();

    let row = customer::Entity::find()
        .filter(customer::Column::Email.eq(&email))
        .one(&state.db)
        .await?;

    let Some(row) = row else {
        return Err(ApiError::unauthorized());
    };

    let customer_id = row.id;
    let password_hash = row
        .password_hash
        .ok_or_else(ApiError::unauthorized)?;

    let ok = password::verify_password(&password_hash, &req.password)?;
    if !ok {
        return Err(ApiError::unauthorized());
    }

    issue_customer_token(&state, customer_id)
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
    validate_credentials(&req)?;
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
    validate_credentials(&req)?;
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
    fn credentials_reject_invalid_email() {
        let req = EmailPasswordRequest {
            email: "not-an-email".to_string(),
            password: "12345678".to_string(),
        };
        assert!(validate_credentials(&req).is_err());
    }

    #[test]
    fn credentials_reject_short_password() {
        let req = EmailPasswordRequest {
            email: "user@example.com".to_string(),
            password: "short".to_string(),
        };
        assert!(validate_credentials(&req).is_err());
    }

    #[test]
    fn credentials_accept_valid() {
        let req = EmailPasswordRequest {
            email: "user@example.com".to_string(),
            password: "12345678".to_string(),
        };
        validate_credentials(&req).expect("valid credentials");
    }
}
