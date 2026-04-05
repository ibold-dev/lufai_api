//! Create sellers/affiliates with email; auto-generated login codes (shown once). Revoke/rotate/delete.

use axum::{
    extract::{Extension, Path},
    http::HeaderMap,
    routing::{delete, post},
    Json, Router,
};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, IntoActiveModel, PaginatorTrait, QueryFilter,
    Set,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

use crate::{
    auth::{
        affiliate as affiliate_util,
        jwt,
        login_code,
        password,
    },
    authz::casbin as casbin_authz,
    db::db_err_is_unique_violation,
    entity::{affiliate, product, seller},
    http::error::ApiError,
    http::limits::{MAX_AFFILIATE_CODE_LEN, MAX_LOGIN_CODE_BYTES},
    state::AppState,
};

pub fn routes() -> Router {
    Router::new()
        .route("/admin/sellers", post(create_seller))
        .route("/admin/sellers/{seller_id}", delete(delete_seller))
        .route(
            "/admin/sellers/{seller_id}/revoke-login",
            post(revoke_seller_login),
        )
        .route(
            "/admin/sellers/{seller_id}/rotate-login",
            post(rotate_seller_login),
        )
        .route("/admin/affiliates", post(create_affiliate))
        .route("/admin/affiliates/{affiliate_id}", delete(delete_affiliate))
        .route(
            "/admin/affiliates/{affiliate_id}/revoke-login",
            post(revoke_affiliate_login),
        )
        .route(
            "/admin/affiliates/{affiliate_id}/rotate-login",
            post(rotate_affiliate_login),
        )
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
    let (prefix, id_str) = sub.split_once(':').ok_or_else(ApiError::unauthorized)?;
    let id = Uuid::parse_str(id_str).map_err(|_| ApiError::unauthorized())?;
    Ok((prefix.to_string(), id))
}

async fn require_admin(headers: &HeaderMap, state: &AppState) -> Result<(String, Uuid), ApiError> {
    let token = bearer_token(headers)?;
    let claims = jwt::decode_access_token(&token, &state.jwt_secret, &state.jwt_issuer)?;
    let sub = claims.sub;
    let (prefix, admin_id) = principal_from_sub(&sub)?;
    if prefix != "admin" {
        return Err(ApiError::forbidden());
    }
    Ok((sub, admin_id))
}

async fn ensure_admin(
    actor_sub: &str,
    obj: &str,
    act: &str,
) -> Result<(), ApiError> {
    let mut enforcer = casbin_authz::create_enforcer().await?;
    let allowed =
        casbin_authz::authorize_owned(&mut enforcer, actor_sub, obj, act, "any").await?;
    if !allowed {
        return Err(ApiError::forbidden());
    }
    Ok(())
}

fn admin_sellers_list_obj() -> &'static str {
    "/admin/sellers/list"
}

fn admin_seller_obj(id: Uuid) -> String {
    format!("/admin/sellers/{id}")
}

fn admin_affiliates_list_obj() -> &'static str {
    "/admin/affiliates/list"
}

fn admin_affiliate_obj(id: Uuid) -> String {
    format!("/admin/affiliates/{id}")
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct DeletedFlagResponse {
    pub deleted: bool,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct RevokedFlagResponse {
    pub revoked: bool,
}

#[derive(Debug, Deserialize, Validate, utoipa::ToSchema)]
pub struct AdminCreateSellerRequest {
    #[validate(email, length(max = 254))]
    pub email: String,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct AdminProvisionResponse {
    pub id: Uuid,
    pub email: String,
    /// Shown once; store securely. Not retrievable later.
    pub login_code: String,
}

#[derive(Debug, Deserialize, Validate, utoipa::ToSchema)]
pub struct AdminCreateAffiliateRequest {
    #[validate(email, length(max = 254))]
    pub email: String,
    /// Customer-facing referral code (unique, stored uppercase).
    #[validate(length(min = 1, max = 32))]
    pub referral_code: String,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct AdminAffiliateProvisionResponse {
    pub id: Uuid,
    pub email: String,
    pub referral_code: String,
    /// Shown once; store securely. Not retrievable later.
    pub login_code: String,
}

fn normalize_email(s: &str) -> String {
    s.trim().to_lowercase()
}

#[utoipa::path(
    post,
    path = "/v1/admin/sellers",
    request_body = AdminCreateSellerRequest,
    responses(
        (status = 200, body = AdminProvisionResponse),
        (status = 400, body = crate::http::error::ProblemDetails),
        (status = 401, body = crate::http::error::ProblemDetails),
        (status = 403, body = crate::http::error::ProblemDetails),
        (status = 409, body = crate::http::error::ProblemDetails),
        (status = 500, body = crate::http::error::ProblemDetails)
    ),
    security(("bearerAuth" = []))
)]
pub(crate) async fn create_seller(
    headers: HeaderMap,
    Extension(state): Extension<AppState>,
    Json(req): Json<AdminCreateSellerRequest>,
) -> Result<Json<AdminProvisionResponse>, ApiError> {
    req.validate()
        .map_err(|_| ApiError::bad_request("invalid email"))?;
    let (actor_sub, _admin_id) = require_admin(&headers, &state).await?;
    ensure_admin(&actor_sub, admin_sellers_list_obj(), "create").await?;

    let email = normalize_email(&req.email);
    if email.is_empty() {
        return Err(ApiError::bad_request("email is required"));
    }

    let login_plain = login_code::generate_login_secret();
    if login_plain.len() > MAX_LOGIN_CODE_BYTES {
        return Err(ApiError::internal("generated login code too long".to_string()));
    }
    let login_hash = password::hash_password(&login_plain)?;

    let id = Uuid::new_v4();
    let now = chrono::Utc::now();
    let active = seller::ActiveModel {
        id: Set(id),
        email: Set(email.clone()),
        full_name: Set(String::new()),
        password_hash: Set(None),
        login_code_hash: Set(Some(login_hash)),
        login_revoked_at: Set(None),
        created_at: Set(now),
        updated_at: Set(now),
    };

    match seller::Entity::insert(active).exec(&state.db).await {
        Ok(_) => {}
        Err(e) => {
            if db_err_is_unique_violation(&e) {
                return Err(ApiError::conflict("seller email already in use"));
            }
            return Err(ApiError::from(e));
        }
    }

    Ok(Json(AdminProvisionResponse {
        id,
        email,
        login_code: login_plain,
    }))
}

#[utoipa::path(
    delete,
    path = "/v1/admin/sellers/{seller_id}",
    params(
        ("seller_id" = Uuid, Path, description = "Seller id")
    ),
    responses(
        (status = 200, body = DeletedFlagResponse),
        (status = 401, body = crate::http::error::ProblemDetails),
        (status = 403, body = crate::http::error::ProblemDetails),
        (status = 404, body = crate::http::error::ProblemDetails),
        (status = 409, body = crate::http::error::ProblemDetails),
        (status = 500, body = crate::http::error::ProblemDetails)
    ),
    security(("bearerAuth" = []))
)]
pub(crate) async fn delete_seller(
    headers: HeaderMap,
    Extension(state): Extension<AppState>,
    Path(seller_id): Path<Uuid>,
) -> Result<Json<DeletedFlagResponse>, ApiError> {
    let (actor_sub, _admin_id) = require_admin(&headers, &state).await?;
    ensure_admin(&actor_sub, &admin_seller_obj(seller_id), "delete").await?;

    let n = product::Entity::find()
        .filter(product::Column::SellerId.eq(seller_id))
        .count(&state.db)
        .await?;
    if n > 0 {
        return Err(ApiError::conflict(
            "seller has products; delete or reassign products first",
        ));
    }

    let res = seller::Entity::delete_many()
        .filter(seller::Column::Id.eq(seller_id))
        .exec(&state.db)
        .await?;
    if res.rows_affected == 0 {
        return Err(ApiError::not_found("seller not found"));
    }
    Ok(Json(DeletedFlagResponse { deleted: true }))
}

#[utoipa::path(
    post,
    path = "/v1/admin/sellers/{seller_id}/revoke-login",
    params(
        ("seller_id" = Uuid, Path, description = "Seller id")
    ),
    responses(
        (status = 200, body = RevokedFlagResponse),
        (status = 401, body = crate::http::error::ProblemDetails),
        (status = 403, body = crate::http::error::ProblemDetails),
        (status = 404, body = crate::http::error::ProblemDetails),
        (status = 500, body = crate::http::error::ProblemDetails)
    ),
    security(("bearerAuth" = []))
)]
pub(crate) async fn revoke_seller_login(
    headers: HeaderMap,
    Extension(state): Extension<AppState>,
    Path(seller_id): Path<Uuid>,
) -> Result<Json<RevokedFlagResponse>, ApiError> {
    let (actor_sub, _admin_id) = require_admin(&headers, &state).await?;
    ensure_admin(&actor_sub, &admin_seller_obj(seller_id), "revoke_login").await?;

    let row = seller::Entity::find_by_id(seller_id)
        .one(&state.db)
        .await?
        .ok_or_else(|| ApiError::not_found("seller not found"))?;
    let now = chrono::Utc::now();
    let mut active: seller::ActiveModel = row.into_active_model();
    active.login_revoked_at = Set(Some(now));
    active.updated_at = Set(now);
    active.update(&state.db).await?;
    Ok(Json(RevokedFlagResponse { revoked: true }))
}

#[utoipa::path(
    post,
    path = "/v1/admin/sellers/{seller_id}/rotate-login",
    params(
        ("seller_id" = Uuid, Path, description = "Seller id")
    ),
    responses(
        (status = 200, body = AdminProvisionResponse),
        (status = 401, body = crate::http::error::ProblemDetails),
        (status = 403, body = crate::http::error::ProblemDetails),
        (status = 404, body = crate::http::error::ProblemDetails),
        (status = 500, body = crate::http::error::ProblemDetails)
    ),
    security(("bearerAuth" = []))
)]
pub(crate) async fn rotate_seller_login(
    headers: HeaderMap,
    Extension(state): Extension<AppState>,
    Path(seller_id): Path<Uuid>,
) -> Result<Json<AdminProvisionResponse>, ApiError> {
    let (actor_sub, _admin_id) = require_admin(&headers, &state).await?;
    ensure_admin(&actor_sub, &admin_seller_obj(seller_id), "rotate_login").await?;

    let row = seller::Entity::find_by_id(seller_id)
        .one(&state.db)
        .await?
        .ok_or_else(|| ApiError::not_found("seller not found"))?;

    let login_plain = login_code::generate_login_secret();
    let login_hash = password::hash_password(&login_plain)?;
    let now = chrono::Utc::now();
    let mut active: seller::ActiveModel = row.into_active_model();
    active.login_code_hash = Set(Some(login_hash));
    active.login_revoked_at = Set(None);
    active.updated_at = Set(now);
    let updated = active.update(&state.db).await?;

    Ok(Json(AdminProvisionResponse {
        id: seller_id,
        email: updated.email,
        login_code: login_plain,
    }))
}

#[utoipa::path(
    post,
    path = "/v1/admin/affiliates",
    request_body = AdminCreateAffiliateRequest,
    responses(
        (status = 200, body = AdminAffiliateProvisionResponse),
        (status = 400, body = crate::http::error::ProblemDetails),
        (status = 401, body = crate::http::error::ProblemDetails),
        (status = 403, body = crate::http::error::ProblemDetails),
        (status = 409, body = crate::http::error::ProblemDetails),
        (status = 500, body = crate::http::error::ProblemDetails)
    ),
    security(("bearerAuth" = []))
)]
pub(crate) async fn create_affiliate(
    headers: HeaderMap,
    Extension(state): Extension<AppState>,
    Json(req): Json<AdminCreateAffiliateRequest>,
) -> Result<Json<AdminAffiliateProvisionResponse>, ApiError> {
    req.validate()
        .map_err(|_| ApiError::bad_request("invalid request"))?;
    let (actor_sub, _admin_id) = require_admin(&headers, &state).await?;
    ensure_admin(&actor_sub, admin_affiliates_list_obj(), "create").await?;

    let email = normalize_email(&req.email);
    if email.is_empty() {
        return Err(ApiError::bad_request("email is required"));
    }

    let code_raw = req.referral_code.trim();
    if code_raw.is_empty() {
        return Err(ApiError::bad_request("referral_code is required"));
    }
    if code_raw.len() > MAX_AFFILIATE_CODE_LEN {
        return Err(ApiError::bad_request("referral_code is too long"));
    }
    let referral_code = affiliate_util::normalize_affiliate_code(code_raw);
    if referral_code.is_empty() {
        return Err(ApiError::bad_request("referral_code is invalid"));
    }

    let login_plain = login_code::generate_login_secret();
    let login_hash = password::hash_password(&login_plain)?;

    let id = Uuid::new_v4();
    let now = chrono::Utc::now();
    let active = affiliate::ActiveModel {
        id: Set(id),
        code: Set(referral_code.clone()),
        email: Set(Some(email.clone())),
        login_code_hash: Set(Some(login_hash)),
        login_revoked_at: Set(None),
        created_at: Set(now),
        updated_at: Set(now),
    };

    match affiliate::Entity::insert(active).exec(&state.db).await {
        Ok(_) => {}
        Err(e) => {
            if db_err_is_unique_violation(&e) {
                return Err(ApiError::conflict(
                    "affiliate email or referral code already in use",
                ));
            }
            return Err(ApiError::from(e));
        }
    }

    Ok(Json(AdminAffiliateProvisionResponse {
        id,
        email,
        referral_code,
        login_code: login_plain,
    }))
}

#[utoipa::path(
    delete,
    path = "/v1/admin/affiliates/{affiliate_id}",
    params(
        ("affiliate_id" = Uuid, Path, description = "Affiliate id")
    ),
    responses(
        (status = 200, body = DeletedFlagResponse),
        (status = 401, body = crate::http::error::ProblemDetails),
        (status = 403, body = crate::http::error::ProblemDetails),
        (status = 404, body = crate::http::error::ProblemDetails),
        (status = 500, body = crate::http::error::ProblemDetails)
    ),
    security(("bearerAuth" = []))
)]
pub(crate) async fn delete_affiliate(
    headers: HeaderMap,
    Extension(state): Extension<AppState>,
    Path(affiliate_id): Path<Uuid>,
) -> Result<Json<DeletedFlagResponse>, ApiError> {
    let (actor_sub, _admin_id) = require_admin(&headers, &state).await?;
    ensure_admin(&actor_sub, &admin_affiliate_obj(affiliate_id), "delete").await?;

    let res = affiliate::Entity::delete_many()
        .filter(affiliate::Column::Id.eq(affiliate_id))
        .exec(&state.db)
        .await?;
    if res.rows_affected == 0 {
        return Err(ApiError::not_found("affiliate not found"));
    }
    Ok(Json(DeletedFlagResponse { deleted: true }))
}

#[utoipa::path(
    post,
    path = "/v1/admin/affiliates/{affiliate_id}/revoke-login",
    params(
        ("affiliate_id" = Uuid, Path, description = "Affiliate id")
    ),
    responses(
        (status = 200, body = RevokedFlagResponse),
        (status = 401, body = crate::http::error::ProblemDetails),
        (status = 403, body = crate::http::error::ProblemDetails),
        (status = 404, body = crate::http::error::ProblemDetails),
        (status = 500, body = crate::http::error::ProblemDetails)
    ),
    security(("bearerAuth" = []))
)]
pub(crate) async fn revoke_affiliate_login(
    headers: HeaderMap,
    Extension(state): Extension<AppState>,
    Path(affiliate_id): Path<Uuid>,
) -> Result<Json<RevokedFlagResponse>, ApiError> {
    let (actor_sub, _admin_id) = require_admin(&headers, &state).await?;
    ensure_admin(&actor_sub, &admin_affiliate_obj(affiliate_id), "revoke_login").await?;

    let row = affiliate::Entity::find_by_id(affiliate_id)
        .one(&state.db)
        .await?
        .ok_or_else(|| ApiError::not_found("affiliate not found"))?;
    let now = chrono::Utc::now();
    let mut active: affiliate::ActiveModel = row.into_active_model();
    active.login_revoked_at = Set(Some(now));
    active.updated_at = Set(now);
    active.update(&state.db).await?;
    Ok(Json(RevokedFlagResponse { revoked: true }))
}

#[utoipa::path(
    post,
    path = "/v1/admin/affiliates/{affiliate_id}/rotate-login",
    params(
        ("affiliate_id" = Uuid, Path, description = "Affiliate id")
    ),
    responses(
        (status = 200, body = AdminAffiliateProvisionResponse),
        (status = 401, body = crate::http::error::ProblemDetails),
        (status = 403, body = crate::http::error::ProblemDetails),
        (status = 404, body = crate::http::error::ProblemDetails),
        (status = 500, body = crate::http::error::ProblemDetails)
    ),
    security(("bearerAuth" = []))
)]
pub(crate) async fn rotate_affiliate_login(
    headers: HeaderMap,
    Extension(state): Extension<AppState>,
    Path(affiliate_id): Path<Uuid>,
) -> Result<Json<AdminAffiliateProvisionResponse>, ApiError> {
    let (actor_sub, _admin_id) = require_admin(&headers, &state).await?;
    ensure_admin(&actor_sub, &admin_affiliate_obj(affiliate_id), "rotate_login").await?;

    let row = affiliate::Entity::find_by_id(affiliate_id)
        .one(&state.db)
        .await?
        .ok_or_else(|| ApiError::not_found("affiliate not found"))?;

    let login_plain = login_code::generate_login_secret();
    let login_hash = password::hash_password(&login_plain)?;
    let now = chrono::Utc::now();
    let mut active: affiliate::ActiveModel = row.into_active_model();
    active.login_code_hash = Set(Some(login_hash));
    active.login_revoked_at = Set(None);
    active.updated_at = Set(now);
    let updated = active.update(&state.db).await?;

    Ok(Json(AdminAffiliateProvisionResponse {
        id: affiliate_id,
        email: updated.email.unwrap_or_default(),
        referral_code: updated.code,
        login_code: login_plain,
    }))
}
