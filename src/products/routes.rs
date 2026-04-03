use axum::{
    extract::Extension,
    http::HeaderMap,
    routing::{delete, patch, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, IntoActiveModel, QueryFilter, QueryOrder, Set,
};
use uuid::Uuid;

use crate::{
    auth::jwt,
    authz::casbin as casbin_authz,
    entity::product,
    http::error::ApiError,
    state::AppState,
};
use casbin::prelude::Enforcer;

pub fn routes() -> Router {
    Router::new()
        // Seller product ads
        .route("/sellers/me/products", post(create_product))
        .route(
            "/sellers/me/products",
            axum::routing::get(list_my_products),
        )
        .route(
            "/sellers/me/products/:product_id",
            patch(update_product),
        )
        .route(
            "/sellers/me/products/:product_id",
            delete(delete_product),
        )
        // Admin moderation
        .route(
            "/admin/products/pending",
            axum::routing::get(list_pending_products),
        )
        .route(
            "/admin/products/:product_id/approve",
            post(approve_product),
        )
        .route(
            "/admin/products/:product_id/reject",
            post(reject_product),
        )
}

#[derive(Debug, Deserialize)]
#[derive(utoipa::ToSchema)]
pub struct CreateProductRequest {
    pub title: String,
    pub description: String,
    /// Price in subunits (e.g., NGN kobo), not base currency.
    pub price_cents: i64,
    pub dimensions: Option<Value>,
}

#[derive(Debug, Deserialize)]
#[derive(utoipa::ToSchema)]
pub struct UpdateProductRequest {
    pub title: Option<String>,
    pub description: Option<String>,
    pub price_cents: Option<i64>,
    pub dimensions: Option<Value>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ProductResponse {
    pub id: Uuid,
    pub seller_id: Uuid,
    pub title: String,
    pub description: String,
    pub price_cents: i64,
    pub currency: String,
    pub dimensions: Option<Value>,
    pub status: String,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct DeleteProductResponse {
    pub deleted: bool,
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

async fn require_seller(
    headers: &HeaderMap,
    state: &AppState,
) -> Result<(String, Uuid), ApiError> {
    let token = bearer_token(headers)?;
    let claims = jwt::decode_access_token(
        &token,
        &state.jwt_secret,
        &state.jwt_issuer,
    )?;
    let sub = claims.sub;
    let (prefix, seller_id) = principal_from_sub(&sub)?;
    if prefix != "seller" {
        return Err(ApiError::forbidden());
    }
    Ok((sub, seller_id))
}

async fn require_admin(
    headers: &HeaderMap,
    state: &AppState,
) -> Result<(String, Uuid), ApiError> {
    let token = bearer_token(headers)?;
    let claims = jwt::decode_access_token(
        &token,
        &state.jwt_secret,
        &state.jwt_issuer,
    )?;
    let sub = claims.sub;
    let (prefix, admin_id) = principal_from_sub(&sub)?;
    if prefix != "admin" {
        return Err(ApiError::forbidden());
    }
    Ok((sub, admin_id))
}

fn product_obj(product_id: Uuid) -> String {
    format!("/products/{product_id}")
}

fn products_collection_obj() -> String {
    "/products/list".to_string()
}

async fn ensure_authorized(
    mut enforcer: Enforcer,
    actor_sub: &str,
    obj: &str,
    act: &str,
    owner: &str,
) -> Result<(), ApiError> {
    let allowed =
        casbin_authz::authorize_owned(&mut enforcer, actor_sub, obj, act, owner)
            .await?;
    if !allowed {
        return Err(ApiError::forbidden());
    }
    Ok(())
}

fn model_to_response(m: product::Model) -> ProductResponse {
    ProductResponse {
        id: m.id,
        seller_id: m.seller_id,
        title: m.title,
        description: m.description,
        price_cents: m.price_cents,
        currency: m.currency,
        dimensions: m.dimensions,
        status: m.status,
    }
}

#[utoipa::path(
    post,
    path = "/v1/sellers/me/products",
    request_body = CreateProductRequest,
    responses(
        (status = 200, body = ProductResponse),
        (status = 400, body = crate::http::error::ProblemDetails),
        (status = 401, body = crate::http::error::ProblemDetails),
        (status = 403, body = crate::http::error::ProblemDetails),
        (status = 409, body = crate::http::error::ProblemDetails),
        (status = 500, body = crate::http::error::ProblemDetails)
    ),
    security(("bearerAuth" = []))
)]
pub(crate) async fn create_product(
    headers: HeaderMap,
    Extension(state): Extension<AppState>,
    Json(req): Json<CreateProductRequest>,
) -> Result<Json<ProductResponse>, ApiError> {
    let (actor_sub, seller_id) = require_seller(&headers, &state).await?;

    let enforcer = casbin_authz::create_enforcer().await?;
    ensure_authorized(
        enforcer,
        &actor_sub,
        &products_collection_obj(),
        "create",
        &actor_sub,
    )
    .await?;

    if req.title.trim().is_empty() {
        return Err(ApiError::bad_request("title is required"));
    }
    if req.description.trim().is_empty() {
        return Err(ApiError::bad_request("description is required"));
    }
    if req.price_cents < 0 {
        return Err(ApiError::bad_request("price_cents must be >= 0"));
    }

    let id = Uuid::new_v4();
    let now = chrono::Utc::now();
    let active = product::ActiveModel {
        id: Set(id),
        seller_id: Set(seller_id),
        title: Set(req.title),
        description: Set(req.description),
        price_cents: Set(req.price_cents),
        currency: Set("NGN".to_string()),
        dimensions: Set(req.dimensions),
        status: Set("pending".to_string()),
        created_at: Set(now),
        updated_at: Set(now),
    };

    let inserted = product::Entity::insert(active)
        .exec_with_returning(&state.db)
        .await?;

    Ok(Json(model_to_response(inserted)))
}

#[utoipa::path(
    get,
    path = "/v1/sellers/me/products",
    responses(
        (status = 200, body = Vec<ProductResponse>),
        (status = 401, body = crate::http::error::ProblemDetails),
        (status = 403, body = crate::http::error::ProblemDetails),
        (status = 500, body = crate::http::error::ProblemDetails)
    ),
    security(("bearerAuth" = []))
)]
pub(crate) async fn list_my_products(
    headers: HeaderMap,
    Extension(state): Extension<AppState>,
) -> Result<Json<Vec<ProductResponse>>, ApiError> {
    let (actor_sub, seller_id) = require_seller(&headers, &state).await?;

    let enforcer = casbin_authz::create_enforcer().await?;
    ensure_authorized(
        enforcer,
        &actor_sub,
        &products_collection_obj(),
        "read",
        &actor_sub,
    )
    .await?;

    let rows = product::Entity::find()
        .filter(product::Column::SellerId.eq(seller_id))
        .order_by_desc(product::Column::CreatedAt)
        .all(&state.db)
        .await?;

    Ok(Json(rows.into_iter().map(model_to_response).collect()))
}

#[utoipa::path(
    patch,
    path = "/v1/sellers/me/products/{product_id}",
    request_body = UpdateProductRequest,
    responses(
        (status = 200, body = ProductResponse),
        (status = 400, body = crate::http::error::ProblemDetails),
        (status = 401, body = crate::http::error::ProblemDetails),
        (status = 403, body = crate::http::error::ProblemDetails),
        (status = 404, body = crate::http::error::ProblemDetails),
        (status = 500, body = crate::http::error::ProblemDetails)
    ),
    security(("bearerAuth" = []))
)]
pub(crate) async fn update_product(
    headers: HeaderMap,
    Extension(state): Extension<AppState>,
    axum::extract::Path(product_id): axum::extract::Path<Uuid>,
    Json(req): Json<UpdateProductRequest>,
) -> Result<Json<ProductResponse>, ApiError> {
    let (actor_sub, seller_id) = require_seller(&headers, &state).await?;

    let enforcer = casbin_authz::create_enforcer().await?;
    ensure_authorized(
        enforcer,
        &actor_sub,
        &product_obj(product_id),
        "update",
        &actor_sub,
    )
    .await?;

    let existing = product::Entity::find()
        .filter(product::Column::Id.eq(product_id))
        .filter(product::Column::SellerId.eq(seller_id))
        .one(&state.db)
        .await?
        .ok_or_else(|| ApiError::not_found("product not found"))?;

    let mut active: product::ActiveModel = existing.into_active_model();
    if let Some(t) = req.title {
        active.title = Set(t);
    }
    if let Some(d) = req.description {
        active.description = Set(d);
    }
    if let Some(p) = req.price_cents {
        active.price_cents = Set(p);
    }
    if let Some(d) = req.dimensions {
        active.dimensions = Set(Some(d));
    }
    active.updated_at = Set(chrono::Utc::now());

    let updated = active.update(&state.db).await?;
    Ok(Json(model_to_response(updated)))
}

#[utoipa::path(
    delete,
    path = "/v1/sellers/me/products/{product_id}",
    responses(
        (status = 200, body = DeleteProductResponse),
        (status = 401, body = crate::http::error::ProblemDetails),
        (status = 403, body = crate::http::error::ProblemDetails),
        (status = 404, body = crate::http::error::ProblemDetails),
        (status = 500, body = crate::http::error::ProblemDetails)
    ),
    security(("bearerAuth" = []))
)]
pub(crate) async fn delete_product(
    headers: HeaderMap,
    Extension(state): Extension<AppState>,
    axum::extract::Path(product_id): axum::extract::Path<Uuid>,
) -> Result<Json<DeleteProductResponse>, ApiError> {
    let (actor_sub, seller_id) = require_seller(&headers, &state).await?;

    let enforcer = casbin_authz::create_enforcer().await?;
    ensure_authorized(
        enforcer,
        &actor_sub,
        &product_obj(product_id),
        "delete",
        &actor_sub,
    )
    .await?;

    let deleted = product::Entity::delete_many()
        .filter(product::Column::Id.eq(product_id))
        .filter(product::Column::SellerId.eq(seller_id))
        .exec(&state.db)
        .await?;

    if deleted.rows_affected == 0 {
        return Err(ApiError::not_found("product not found"));
    }

    Ok(Json(DeleteProductResponse { deleted: true }))
}

#[utoipa::path(
    get,
    path = "/v1/admin/products/pending",
    responses(
        (status = 200, body = Vec<ProductResponse>),
        (status = 401, body = crate::http::error::ProblemDetails),
        (status = 403, body = crate::http::error::ProblemDetails),
        (status = 500, body = crate::http::error::ProblemDetails)
    ),
    security(("bearerAuth" = []))
)]
pub(crate) async fn list_pending_products(
    headers: HeaderMap,
    Extension(state): Extension<AppState>,
) -> Result<Json<Vec<ProductResponse>>, ApiError> {
    let (actor_sub, _admin_id) = require_admin(&headers, &state).await?;

    let enforcer = casbin_authz::create_enforcer().await?;
    ensure_authorized(
        enforcer,
        &actor_sub,
        &products_collection_obj(),
        "read",
        &actor_sub,
    )
    .await?;

    let rows = product::Entity::find()
        .filter(product::Column::Status.eq("pending"))
        .order_by_desc(product::Column::CreatedAt)
        .all(&state.db)
        .await?;

    Ok(Json(rows.into_iter().map(model_to_response).collect()))
}

#[utoipa::path(
    post,
    path = "/v1/admin/products/{product_id}/approve",
    responses(
        (status = 200, body = ProductResponse),
        (status = 401, body = crate::http::error::ProblemDetails),
        (status = 403, body = crate::http::error::ProblemDetails),
        (status = 404, body = crate::http::error::ProblemDetails),
        (status = 500, body = crate::http::error::ProblemDetails)
    ),
    security(("bearerAuth" = []))
)]
pub(crate) async fn approve_product(
    headers: HeaderMap,
    Extension(state): Extension<AppState>,
    axum::extract::Path(product_id): axum::extract::Path<Uuid>,
) -> Result<Json<ProductResponse>, ApiError> {
    let (actor_sub, _admin_id) = require_admin(&headers, &state).await?;

    let enforcer = casbin_authz::create_enforcer().await?;
    ensure_authorized(
        enforcer,
        &actor_sub,
        &product_obj(product_id),
        "approve",
        &actor_sub,
    )
    .await?;

    let existing = product::Entity::find_by_id(product_id)
        .one(&state.db)
        .await?
        .ok_or_else(|| ApiError::not_found("product not found"))?;

    let mut active = existing.into_active_model();
    active.status = Set("approved".to_string());
    active.updated_at = Set(chrono::Utc::now());
    let updated = active.update(&state.db).await?;

    Ok(Json(model_to_response(updated)))
}

#[utoipa::path(
    post,
    path = "/v1/admin/products/{product_id}/reject",
    responses(
        (status = 200, body = ProductResponse),
        (status = 401, body = crate::http::error::ProblemDetails),
        (status = 403, body = crate::http::error::ProblemDetails),
        (status = 404, body = crate::http::error::ProblemDetails),
        (status = 500, body = crate::http::error::ProblemDetails)
    ),
    security(("bearerAuth" = []))
)]
pub(crate) async fn reject_product(
    headers: HeaderMap,
    Extension(state): Extension<AppState>,
    axum::extract::Path(product_id): axum::extract::Path<Uuid>,
) -> Result<Json<ProductResponse>, ApiError> {
    let (actor_sub, _admin_id) = require_admin(&headers, &state).await?;

    let enforcer = casbin_authz::create_enforcer().await?;
    ensure_authorized(
        enforcer,
        &actor_sub,
        &product_obj(product_id),
        "reject",
        &actor_sub,
    )
    .await?;

    let existing = product::Entity::find_by_id(product_id)
        .one(&state.db)
        .await?
        .ok_or_else(|| ApiError::not_found("product not found"))?;

    let mut active = existing.into_active_model();
    active.status = Set("rejected".to_string());
    active.updated_at = Set(chrono::Utc::now());
    let updated = active.update(&state.db).await?;

    Ok(Json(model_to_response(updated)))
}
