use axum::{
    extract::Extension,
    http::HeaderMap,
    routing::{delete, patch, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, EntityTrait, IntoActiveModel, QueryFilter,
    QueryOrder, Set, TransactionTrait,
};
use std::collections::HashMap;
use uuid::Uuid;

use crate::{
    auth::jwt,
    authz::casbin as casbin_authz,
    entity::{product, product_image},
    http::error::ApiError,
    http::limits::{
        MAX_PRODUCT_DESCRIPTION_LEN, MAX_PRODUCT_IMAGE_ALT_LEN, MAX_PRODUCT_IMAGE_URL_LEN,
        MAX_PRODUCT_IMAGES_PER_PRODUCT, MAX_PRODUCT_TITLE_LEN,
    },
    http::validation::check_optional_json_value_size,
    state::AppState,
};
use casbin::prelude::Enforcer;

/// Axum 0.8+ path captures must use `{name}` syntax, not `:name`.
pub fn routes() -> Router {
    Router::new()
        // Seller product ads
        .route("/sellers/me/products", post(create_product))
        .route(
            "/sellers/me/products",
            axum::routing::get(list_my_products),
        )
        .route(
            "/sellers/me/products/{product_id}",
            patch(update_product),
        )
        .route(
            "/sellers/me/products/{product_id}",
            delete(delete_product),
        )
        // Admin moderation
        .route(
            "/admin/products/pending",
            axum::routing::get(list_pending_products),
        )
        .route(
            "/admin/products/{product_id}/approve",
            post(approve_product),
        )
        .route(
            "/admin/products/{product_id}/reject",
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
    /// Gallery. When non-empty, exactly one entry must have `is_primary: true`.
    #[serde(default)]
    pub images: Vec<ProductImageInput>,
}

#[derive(Debug, Deserialize)]
#[derive(utoipa::ToSchema)]
pub struct UpdateProductRequest {
    pub title: Option<String>,
    pub description: Option<String>,
    pub price_cents: Option<i64>,
    pub dimensions: Option<Value>,
    /// When set, replaces the entire image set for this product (omit to leave unchanged).
    pub images: Option<Vec<ProductImageInput>>,
}

#[derive(Debug, Deserialize, Serialize, utoipa::ToSchema)]
pub struct ProductImageInput {
    /// Public HTTPS URL (e.g. CDN). Trimmed before storage.
    pub url: String,
    /// Lower values appear first; defaults to the index in the `images` array.
    pub sort_order: Option<i32>,
    #[serde(default)]
    pub is_primary: bool,
    pub alt_text: Option<String>,
}

#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct ProductImageResponse {
    pub id: Uuid,
    pub url: String,
    pub sort_order: i32,
    pub is_primary: bool,
    pub alt_text: Option<String>,
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
    /// Ordered by `sort_order`, then `id`.
    pub images: Vec<ProductImageResponse>,
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

fn validate_create_product(req: &CreateProductRequest) -> Result<(), ApiError> {
    if req.title.chars().count() > MAX_PRODUCT_TITLE_LEN {
        return Err(ApiError::bad_request("title is too long"));
    }
    if req.description.chars().count() > MAX_PRODUCT_DESCRIPTION_LEN {
        return Err(ApiError::bad_request("description is too long"));
    }
    check_optional_json_value_size("dimensions", &req.dimensions)?;
    validate_product_images(&req.images)?;
    Ok(())
}

fn validate_update_product(req: &UpdateProductRequest) -> Result<(), ApiError> {
    if let Some(ref t) = req.title {
        if t.trim().is_empty() {
            return Err(ApiError::bad_request("title must not be empty"));
        }
        if t.chars().count() > MAX_PRODUCT_TITLE_LEN {
            return Err(ApiError::bad_request("title is too long"));
        }
    }
    if let Some(ref d) = req.description {
        if d.trim().is_empty() {
            return Err(ApiError::bad_request("description must not be empty"));
        }
        if d.chars().count() > MAX_PRODUCT_DESCRIPTION_LEN {
            return Err(ApiError::bad_request("description is too long"));
        }
    }
    if let Some(p) = req.price_cents
        && p < 0
    {
        return Err(ApiError::bad_request("price_cents must be >= 0"));
    }
    check_optional_json_value_size("dimensions", &req.dimensions)?;
    if let Some(ref imgs) = req.images {
        validate_product_images(imgs)?;
    }
    Ok(())
}

fn validate_product_images(inputs: &[ProductImageInput]) -> Result<(), ApiError> {
    if inputs.len() > MAX_PRODUCT_IMAGES_PER_PRODUCT {
        return Err(ApiError::bad_request("too many images"));
    }
    let mut primary_count = 0usize;
    for img in inputs {
        let u = img.url.trim();
        if u.is_empty() {
            return Err(ApiError::bad_request("image url must not be empty"));
        }
        if u.len() > MAX_PRODUCT_IMAGE_URL_LEN {
            return Err(ApiError::bad_request("image url is too long"));
        }
        if img.is_primary {
            primary_count += 1;
        }
        if let Some(ref a) = img.alt_text
            && a.chars().count() > MAX_PRODUCT_IMAGE_ALT_LEN
        {
            return Err(ApiError::bad_request("image alt_text is too long"));
        }
    }
    if !inputs.is_empty() && primary_count != 1 {
        return Err(ApiError::bad_request(
            "exactly one image must have is_primary true",
        ));
    }
    Ok(())
}

fn image_row_to_response(m: product_image::Model) -> ProductImageResponse {
    ProductImageResponse {
        id: m.id,
        url: m.url,
        sort_order: m.sort_order,
        is_primary: m.is_primary,
        alt_text: m.alt_text,
    }
}

async fn load_images_for_product(
    db: &sea_orm::DatabaseConnection,
    product_id: Uuid,
) -> Result<Vec<ProductImageResponse>, ApiError> {
    let rows = product_image::Entity::find()
        .filter(product_image::Column::ProductId.eq(product_id))
        .order_by_asc(product_image::Column::SortOrder)
        .order_by_asc(product_image::Column::Id)
        .all(db)
        .await?;
    Ok(rows.into_iter().map(image_row_to_response).collect())
}

async fn load_images_by_product_ids(
    db: &sea_orm::DatabaseConnection,
    ids: &[Uuid],
) -> Result<HashMap<Uuid, Vec<ProductImageResponse>>, ApiError> {
    if ids.is_empty() {
        return Ok(HashMap::new());
    }
    let id_vec: Vec<Uuid> = ids.to_vec();
    let rows = product_image::Entity::find()
        .filter(product_image::Column::ProductId.is_in(id_vec))
        .order_by_asc(product_image::Column::SortOrder)
        .order_by_asc(product_image::Column::Id)
        .all(db)
        .await?;
    let mut map: HashMap<Uuid, Vec<ProductImageResponse>> = HashMap::new();
    for r in rows {
        map.entry(r.product_id)
            .or_default()
            .push(image_row_to_response(r));
    }
    Ok(map)
}

fn model_to_response(m: product::Model, images: Vec<ProductImageResponse>) -> ProductResponse {
    ProductResponse {
        id: m.id,
        seller_id: m.seller_id,
        title: m.title,
        description: m.description,
        price_cents: m.price_cents,
        currency: m.currency,
        dimensions: m.dimensions,
        status: m.status,
        images,
    }
}

async fn insert_product_images<C: ConnectionTrait>(
    db: &C,
    product_id: Uuid,
    inputs: &[ProductImageInput],
    now: chrono::DateTime<chrono::Utc>,
) -> Result<(), ApiError> {
    for (idx, input) in inputs.iter().enumerate() {
        let sort_order = input.sort_order.unwrap_or(idx as i32);
        let url = input.url.trim().to_string();
        let am = product_image::ActiveModel {
            id: Set(Uuid::new_v4()),
            product_id: Set(product_id),
            url: Set(url),
            sort_order: Set(sort_order),
            is_primary: Set(input.is_primary),
            alt_text: Set(input.alt_text.clone()),
            created_at: Set(now),
            updated_at: Set(now),
        };
        product_image::Entity::insert(am).exec(db).await?;
    }
    Ok(())
}

async fn replace_product_images<C: ConnectionTrait>(
    db: &C,
    product_id: Uuid,
    inputs: &[ProductImageInput],
    now: chrono::DateTime<chrono::Utc>,
) -> Result<(), ApiError> {
    validate_product_images(inputs)?;
    product_image::Entity::delete_many()
        .filter(product_image::Column::ProductId.eq(product_id))
        .exec(db)
        .await?;
    if inputs.is_empty() {
        return Ok(());
    }
    insert_product_images(db, product_id, inputs, now).await
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

    validate_create_product(&req)?;

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

    let txn = state.db.begin().await?;
    product::Entity::insert(active).exec(&txn).await?;
    if !req.images.is_empty() {
        insert_product_images(&txn, id, &req.images, now).await?;
    }
    txn.commit().await?;

    let inserted = product::Entity::find_by_id(id)
        .one(&state.db)
        .await?
        .ok_or_else(|| ApiError::internal("product insert missing".to_string()))?;
    let images = load_images_for_product(&state.db, id).await?;
    Ok(Json(model_to_response(inserted, images)))
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

    let ids: Vec<Uuid> = rows.iter().map(|r| r.id).collect();
    let img_map = load_images_by_product_ids(&state.db, &ids).await?;
    let out = rows
        .into_iter()
        .map(|m| {
            let imgs = img_map.get(&m.id).cloned().unwrap_or_default();
            model_to_response(m, imgs)
        })
        .collect();
    Ok(Json(out))
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

    validate_update_product(&req)?;

    let existing = product::Entity::find()
        .filter(product::Column::Id.eq(product_id))
        .filter(product::Column::SellerId.eq(seller_id))
        .one(&state.db)
        .await?
        .ok_or_else(|| ApiError::not_found("product not found"))?;

    let now = chrono::Utc::now();
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
    active.updated_at = Set(now);

    if let Some(ref imgs) = req.images {
        let txn = state.db.begin().await?;
        let updated = active.update(&txn).await?;
        replace_product_images(&txn, product_id, imgs, now).await?;
        txn.commit().await?;
        let images = load_images_for_product(&state.db, product_id).await?;
        return Ok(Json(model_to_response(updated, images)));
    }

    let updated = active.update(&state.db).await?;
    let images = load_images_for_product(&state.db, product_id).await?;
    Ok(Json(model_to_response(updated, images)))
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

    let ids: Vec<Uuid> = rows.iter().map(|r| r.id).collect();
    let img_map = load_images_by_product_ids(&state.db, &ids).await?;
    let out = rows
        .into_iter()
        .map(|m| {
            let imgs = img_map.get(&m.id).cloned().unwrap_or_default();
            model_to_response(m, imgs)
        })
        .collect();
    Ok(Json(out))
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
    let images = load_images_for_product(&state.db, product_id).await?;

    Ok(Json(model_to_response(updated, images)))
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
    let images = load_images_for_product(&state.db, product_id).await?;

    Ok(Json(model_to_response(updated, images)))
}
