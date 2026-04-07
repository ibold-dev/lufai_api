//! Seller and admin HTTP handlers for promotions (discount campaigns).

use axum::{
    Json, Router,
    extract::Extension,
    http::HeaderMap,
    routing::{delete, get, patch, post},
};
use casbin::prelude::Enforcer;
use chrono::{DateTime, Utc};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, EntityTrait, IntoActiveModel, QueryFilter,
    QueryOrder, Set, TransactionTrait,
};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use uuid::Uuid;

use crate::{
    auth::jwt,
    authz::casbin as casbin_authz,
    entity::{product, promotion, promotion_product},
    http::error::ApiError,
    payments::methods as payment_methods,
    http::limits::{MAX_PROMOTION_NAME_LEN, MAX_PROMOTION_PRODUCT_IDS},
    state::AppState,
};

pub fn routes() -> Router {
    Router::new()
        .route("/sellers/me/promotions", post(create_seller_promotion))
        .route("/sellers/me/promotions", get(list_seller_promotions))
        .route(
            "/sellers/me/promotions/{promotion_id}",
            get(get_seller_promotion),
        )
        .route(
            "/sellers/me/promotions/{promotion_id}",
            patch(update_seller_promotion),
        )
        .route(
            "/sellers/me/promotions/{promotion_id}",
            delete(delete_seller_promotion),
        )
        .route("/admin/promotions", post(create_admin_promotion))
        .route("/admin/promotions", get(list_admin_promotions))
        .route("/admin/promotions/{promotion_id}", get(get_admin_promotion))
        .route(
            "/admin/promotions/{promotion_id}",
            patch(update_admin_promotion),
        )
        .route(
            "/admin/promotions/{promotion_id}",
            delete(delete_admin_promotion),
        )
}

#[derive(Debug, Deserialize, Serialize, utoipa::ToSchema)]
pub struct CreatePromotionRequest {
    pub name: String,
    #[serde(default = "default_status_draft")]
    pub status: String,
    pub starts_at: DateTime<Utc>,
    pub ends_at: DateTime<Utc>,
    pub discount_kind: String,
    pub discount_percent: Option<i32>,
    pub discount_fixed_cents: Option<i64>,
    #[serde(default)]
    pub priority: i32,
    /// When set, discounted lines use only these methods (overrides product defaults).
    pub allowed_payment_methods: Option<Vec<String>>,
    pub product_ids: Vec<Uuid>,
}

fn default_status_draft() -> String {
    "draft".to_string()
}

#[derive(Debug, Deserialize, Serialize, utoipa::ToSchema)]
pub struct UpdatePromotionRequest {
    pub name: Option<String>,
    pub status: Option<String>,
    pub starts_at: Option<DateTime<Utc>>,
    pub ends_at: Option<DateTime<Utc>>,
    pub discount_kind: Option<String>,
    pub discount_percent: Option<i32>,
    pub discount_fixed_cents: Option<i64>,
    pub priority: Option<i32>,
    /// Empty list clears override (inherit from product). Omit to leave unchanged.
    pub allowed_payment_methods: Option<Vec<String>>,
    pub product_ids: Option<Vec<Uuid>>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct PromotionResponse {
    pub id: Uuid,
    /// `None` for platform-wide campaigns (admin only).
    pub seller_id: Option<Uuid>,
    pub name: String,
    pub status: String,
    pub starts_at: DateTime<Utc>,
    pub ends_at: DateTime<Utc>,
    pub discount_kind: String,
    pub discount_percent: Option<i32>,
    pub discount_fixed_cents: Option<i64>,
    pub priority: i32,
    /// When `None`, discounted lines inherit product payment rules.
    pub allowed_payment_methods: Option<Vec<String>>,
    pub product_ids: Vec<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct DeletePromotionResponse {
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
    let (prefix, id_str) = sub.split_once(':').ok_or_else(ApiError::unauthorized)?;

    let id = Uuid::parse_str(id_str).map_err(|_| ApiError::unauthorized())?;

    Ok((prefix.to_string(), id))
}

async fn require_seller(headers: &HeaderMap, state: &AppState) -> Result<(String, Uuid), ApiError> {
    let token = bearer_token(headers)?;
    let claims = jwt::decode_access_token(&token, &state.jwt_secret, &state.jwt_issuer)?;
    let sub = claims.sub;
    let (prefix, seller_id) = principal_from_sub(&sub)?;
    if prefix != "seller" {
        return Err(ApiError::forbidden());
    }
    Ok((sub, seller_id))
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

fn promotion_obj(id: Uuid) -> String {
    format!("/promotions/{id}")
}

fn promotions_collection_obj() -> String {
    "/promotions/list".to_string()
}

fn admin_promotion_obj(id: Uuid) -> String {
    format!("/admin/promotions/{id}")
}

fn admin_promotions_collection_obj() -> String {
    "/admin/promotions/list".to_string()
}

async fn ensure_authorized(
    mut enforcer: Enforcer,
    actor_sub: &str,
    obj: &str,
    act: &str,
    owner: &str,
) -> Result<(), ApiError> {
    let allowed = casbin_authz::authorize_owned(&mut enforcer, actor_sub, obj, act, owner).await?;
    if !allowed {
        return Err(ApiError::forbidden());
    }
    Ok(())
}

fn validate_status(s: &str) -> Result<(), ApiError> {
    if matches!(s, "draft" | "active" | "ended") {
        return Ok(());
    }
    Err(ApiError::bad_request(
        "status must be draft, active, or ended",
    ))
}

fn validate_discount_fields(
    kind: &str,
    discount_percent: Option<i32>,
    discount_fixed_cents: Option<i64>,
) -> Result<(), ApiError> {
    match kind {
        "percent" => {
            let Some(p) = discount_percent else {
                return Err(ApiError::bad_request(
                    "discount_percent is required for percent",
                ));
            };
            if !(1..=100).contains(&p) {
                return Err(ApiError::bad_request(
                    "discount_percent must be between 1 and 100",
                ));
            }
            if discount_fixed_cents.is_some() {
                return Err(ApiError::bad_request(
                    "discount_fixed_cents must be omitted for percent",
                ));
            }
        }
        "fixed_unit" => {
            let Some(f) = discount_fixed_cents else {
                return Err(ApiError::bad_request(
                    "discount_fixed_cents is required for fixed_unit",
                ));
            };
            if f < 0 {
                return Err(ApiError::bad_request("discount_fixed_cents must be >= 0"));
            }
            if discount_percent.is_some() {
                return Err(ApiError::bad_request(
                    "discount_percent must be omitted for fixed_unit",
                ));
            }
        }
        _ => {
            return Err(ApiError::bad_request(
                "discount_kind must be percent or fixed_unit",
            ));
        }
    }
    Ok(())
}

fn validate_create(req: &CreatePromotionRequest) -> Result<(), ApiError> {
    let name = req.name.trim();
    if name.is_empty() {
        return Err(ApiError::bad_request("name must not be empty"));
    }
    if name.chars().count() > MAX_PROMOTION_NAME_LEN {
        return Err(ApiError::bad_request("name is too long"));
    }
    validate_status(&req.status)?;
    if req.ends_at <= req.starts_at {
        return Err(ApiError::bad_request("ends_at must be after starts_at"));
    }
    validate_discount_fields(
        &req.discount_kind,
        req.discount_percent,
        req.discount_fixed_cents,
    )?;
    if req.product_ids.is_empty() {
        return Err(ApiError::bad_request("product_ids must not be empty"));
    }
    if req.product_ids.len() > MAX_PROMOTION_PRODUCT_IDS {
        return Err(ApiError::bad_request("too many products in promotion"));
    }
    let set: HashSet<Uuid> = req.product_ids.iter().copied().collect();
    if set.len() != req.product_ids.len() {
        return Err(ApiError::bad_request("product_ids must be unique"));
    }
    if let Some(ref m) = req.allowed_payment_methods {
        payment_methods::validate_payment_methods_list(m)?;
    }
    Ok(())
}

fn validate_update_patch(req: &UpdatePromotionRequest) -> Result<(), ApiError> {
    if let Some(ref s) = req.status {
        validate_status(s)?;
    }
    if let Some(ref ids) = req.product_ids {
        if ids.is_empty() {
            return Err(ApiError::bad_request("product_ids must not be empty"));
        }
        if ids.len() > MAX_PROMOTION_PRODUCT_IDS {
            return Err(ApiError::bad_request("too many products in promotion"));
        }
        let set: HashSet<Uuid> = ids.iter().copied().collect();
        if set.len() != ids.len() {
            return Err(ApiError::bad_request("product_ids must be unique"));
        }
    }
    if let Some(ref n) = req.name {
        let t = n.trim();
        if t.is_empty() {
            return Err(ApiError::bad_request("name must not be empty"));
        }
        if t.chars().count() > MAX_PROMOTION_NAME_LEN {
            return Err(ApiError::bad_request("name is too long"));
        }
    }
    if let Some(ref m) = req.allowed_payment_methods {
        if !m.is_empty() {
            payment_methods::validate_payment_methods_list(m)?;
        }
    }
    Ok(())
}

fn merged_time_window(
    existing: &promotion::Model,
    req: &UpdatePromotionRequest,
) -> Result<(DateTime<Utc>, DateTime<Utc>), ApiError> {
    let s = req.starts_at.unwrap_or(existing.starts_at);
    let e = req.ends_at.unwrap_or(existing.ends_at);
    if e <= s {
        return Err(ApiError::bad_request("ends_at must be after starts_at"));
    }
    Ok((s, e))
}

fn merge_discount_update(
    existing: &promotion::Model,
    req: &UpdatePromotionRequest,
) -> Result<(String, Option<i32>, Option<i64>), ApiError> {
    let any = req.discount_kind.is_some()
        || req.discount_percent.is_some()
        || req.discount_fixed_cents.is_some();
    if !any {
        return Ok((
            existing.discount_kind.clone(),
            existing.discount_percent,
            existing.discount_fixed_cents,
        ));
    }
    let kind = req
        .discount_kind
        .clone()
        .unwrap_or_else(|| existing.discount_kind.clone());
    let pct = if req.discount_percent.is_some() {
        req.discount_percent
    } else if req.discount_kind.is_some() {
        None
    } else {
        existing.discount_percent
    };
    let fixed = if req.discount_fixed_cents.is_some() {
        req.discount_fixed_cents
    } else if req.discount_kind.is_some() {
        None
    } else {
        existing.discount_fixed_cents
    };
    validate_discount_fields(&kind, pct, fixed)?;
    Ok((kind, pct, fixed))
}

async fn load_product_ids(
    db: &impl ConnectionTrait,
    promotion_id: Uuid,
) -> Result<Vec<Uuid>, ApiError> {
    let rows = promotion_product::Entity::find()
        .filter(promotion_product::Column::PromotionId.eq(promotion_id))
        .all(db)
        .await?;
    let mut ids: Vec<Uuid> = rows.into_iter().map(|r| r.product_id).collect();
    ids.sort();
    Ok(ids)
}

async fn replace_promotion_products<C: ConnectionTrait>(
    db: &C,
    promotion_id: Uuid,
    product_ids: &[Uuid],
) -> Result<(), ApiError> {
    promotion_product::Entity::delete_many()
        .filter(promotion_product::Column::PromotionId.eq(promotion_id))
        .exec(db)
        .await?;
    for &pid in product_ids {
        let am = promotion_product::ActiveModel {
            promotion_id: Set(promotion_id),
            product_id: Set(pid),
        };
        promotion_product::Entity::insert(am).exec(db).await?;
    }
    Ok(())
}

async fn assert_seller_owns_products(
    db: &impl ConnectionTrait,
    seller_id: Uuid,
    product_ids: &[Uuid],
) -> Result<(), ApiError> {
    let rows = product::Entity::find()
        .filter(product::Column::Id.is_in(product_ids.to_vec()))
        .filter(product::Column::SellerId.eq(seller_id))
        .all(db)
        .await?;
    if rows.len() != product_ids.len() {
        return Err(ApiError::bad_request(
            "one or more products are missing or not owned by this seller",
        ));
    }
    Ok(())
}

async fn assert_products_approved(
    db: &impl ConnectionTrait,
    product_ids: &[Uuid],
) -> Result<(), ApiError> {
    let rows = product::Entity::find()
        .filter(product::Column::Id.is_in(product_ids.to_vec()))
        .filter(product::Column::Status.eq("approved"))
        .all(db)
        .await?;
    if rows.len() != product_ids.len() {
        return Err(ApiError::bad_request(
            "one or more products are missing or not approved",
        ));
    }
    Ok(())
}

async fn model_to_response(
    db: &impl ConnectionTrait,
    m: promotion::Model,
) -> Result<PromotionResponse, ApiError> {
    let product_ids = load_product_ids(db, m.id).await?;
    Ok(PromotionResponse {
        id: m.id,
        seller_id: m.seller_id,
        name: m.name,
        status: m.status,
        starts_at: m.starts_at,
        ends_at: m.ends_at,
        discount_kind: m.discount_kind,
        discount_percent: m.discount_percent,
        discount_fixed_cents: m.discount_fixed_cents,
        priority: m.priority,
        allowed_payment_methods: payment_methods::json_opt_to_methods_vec(
            &m.allowed_payment_methods,
        ),
        product_ids,
        created_at: m.created_at,
        updated_at: m.updated_at,
    })
}

#[utoipa::path(
    post,
    path = "/v1/sellers/me/promotions",
    request_body = CreatePromotionRequest,
    responses(
        (status = 200, body = PromotionResponse),
        (status = 400, body = crate::http::error::ProblemDetails),
        (status = 401, body = crate::http::error::ProblemDetails),
        (status = 403, body = crate::http::error::ProblemDetails),
        (status = 500, body = crate::http::error::ProblemDetails)
    ),
    security(("bearerAuth" = []))
)]
pub(crate) async fn create_seller_promotion(
    headers: HeaderMap,
    Extension(state): Extension<AppState>,
    Json(req): Json<CreatePromotionRequest>,
) -> Result<Json<PromotionResponse>, ApiError> {
    let (actor_sub, seller_id) = require_seller(&headers, &state).await?;
    let enforcer = casbin_authz::create_enforcer().await?;
    ensure_authorized(
        enforcer,
        &actor_sub,
        &promotions_collection_obj(),
        "create",
        &actor_sub,
    )
    .await?;

    validate_create(&req)?;
    assert_seller_owns_products(&state.db, seller_id, &req.product_ids).await?;

    let id = Uuid::new_v4();
    let now = Utc::now();
    let am = promotion::ActiveModel {
        id: Set(id),
        seller_id: Set(Some(seller_id)),
        name: Set(req.name.trim().to_string()),
        status: Set(req.status.clone()),
        starts_at: Set(req.starts_at),
        ends_at: Set(req.ends_at),
        discount_kind: Set(req.discount_kind.clone()),
        discount_percent: Set(req.discount_percent),
        discount_fixed_cents: Set(req.discount_fixed_cents),
        priority: Set(req.priority),
        allowed_payment_methods: Set(payment_methods::opt_vec_to_json_methods(
            req.allowed_payment_methods.clone(),
        )?),
        created_at: Set(now),
        updated_at: Set(now),
    };

    let txn = state.db.begin().await?;
    promotion::Entity::insert(am).exec(&txn).await?;
    replace_promotion_products(&txn, id, &req.product_ids).await?;
    txn.commit().await?;

    let row = promotion::Entity::find_by_id(id)
        .one(&state.db)
        .await?
        .ok_or_else(|| ApiError::internal("promotion insert missing".to_string()))?;
    Ok(Json(model_to_response(&state.db, row).await?))
}

#[utoipa::path(
    get,
    path = "/v1/sellers/me/promotions",
    responses(
        (status = 200, body = Vec<PromotionResponse>),
        (status = 401, body = crate::http::error::ProblemDetails),
        (status = 403, body = crate::http::error::ProblemDetails),
        (status = 500, body = crate::http::error::ProblemDetails)
    ),
    security(("bearerAuth" = []))
)]
pub(crate) async fn list_seller_promotions(
    headers: HeaderMap,
    Extension(state): Extension<AppState>,
) -> Result<Json<Vec<PromotionResponse>>, ApiError> {
    let (actor_sub, seller_id) = require_seller(&headers, &state).await?;
    let enforcer = casbin_authz::create_enforcer().await?;
    ensure_authorized(
        enforcer,
        &actor_sub,
        &promotions_collection_obj(),
        "read",
        &actor_sub,
    )
    .await?;

    let rows = promotion::Entity::find()
        .filter(promotion::Column::SellerId.eq(Some(seller_id)))
        .order_by_desc(promotion::Column::CreatedAt)
        .all(&state.db)
        .await?;

    let mut out = Vec::with_capacity(rows.len());
    for m in rows {
        out.push(model_to_response(&state.db, m).await?);
    }
    Ok(Json(out))
}

#[utoipa::path(
    get,
    path = "/v1/sellers/me/promotions/{promotion_id}",
    responses(
        (status = 200, body = PromotionResponse),
        (status = 401, body = crate::http::error::ProblemDetails),
        (status = 403, body = crate::http::error::ProblemDetails),
        (status = 404, body = crate::http::error::ProblemDetails),
        (status = 500, body = crate::http::error::ProblemDetails)
    ),
    security(("bearerAuth" = []))
)]
pub(crate) async fn get_seller_promotion(
    headers: HeaderMap,
    Extension(state): Extension<AppState>,
    axum::extract::Path(promotion_id): axum::extract::Path<Uuid>,
) -> Result<Json<PromotionResponse>, ApiError> {
    let (actor_sub, seller_id) = require_seller(&headers, &state).await?;
    let enforcer = casbin_authz::create_enforcer().await?;
    ensure_authorized(
        enforcer,
        &actor_sub,
        &promotion_obj(promotion_id),
        "read",
        &actor_sub,
    )
    .await?;

    let row = promotion::Entity::find_by_id(promotion_id)
        .filter(promotion::Column::SellerId.eq(Some(seller_id)))
        .one(&state.db)
        .await?
        .ok_or_else(|| ApiError::not_found("promotion not found"))?;

    Ok(Json(model_to_response(&state.db, row).await?))
}

#[utoipa::path(
    patch,
    path = "/v1/sellers/me/promotions/{promotion_id}",
    request_body = UpdatePromotionRequest,
    responses(
        (status = 200, body = PromotionResponse),
        (status = 400, body = crate::http::error::ProblemDetails),
        (status = 401, body = crate::http::error::ProblemDetails),
        (status = 403, body = crate::http::error::ProblemDetails),
        (status = 404, body = crate::http::error::ProblemDetails),
        (status = 500, body = crate::http::error::ProblemDetails)
    ),
    security(("bearerAuth" = []))
)]
pub(crate) async fn update_seller_promotion(
    headers: HeaderMap,
    Extension(state): Extension<AppState>,
    axum::extract::Path(promotion_id): axum::extract::Path<Uuid>,
    Json(req): Json<UpdatePromotionRequest>,
) -> Result<Json<PromotionResponse>, ApiError> {
    let (actor_sub, seller_id) = require_seller(&headers, &state).await?;
    let enforcer = casbin_authz::create_enforcer().await?;
    ensure_authorized(
        enforcer,
        &actor_sub,
        &promotion_obj(promotion_id),
        "update",
        &actor_sub,
    )
    .await?;

    let existing = promotion::Entity::find_by_id(promotion_id)
        .filter(promotion::Column::SellerId.eq(Some(seller_id)))
        .one(&state.db)
        .await?
        .ok_or_else(|| ApiError::not_found("promotion not found"))?;

    validate_update_patch(&req)?;
    if let Some(ref ids) = req.product_ids {
        assert_seller_owns_products(&state.db, seller_id, ids).await?;
    }

    let (starts_at, ends_at) = merged_time_window(&existing, &req)?;
    let (discount_kind, discount_percent, discount_fixed_cents) =
        merge_discount_update(&existing, &req)?;

    let now = Utc::now();
    let mut active: promotion::ActiveModel = existing.into_active_model();
    if let Some(n) = req.name {
        active.name = Set(n.trim().to_string());
    }
    if let Some(s) = req.status {
        active.status = Set(s);
    }
    active.starts_at = Set(starts_at);
    active.ends_at = Set(ends_at);
    active.discount_kind = Set(discount_kind);
    active.discount_percent = Set(discount_percent);
    active.discount_fixed_cents = Set(discount_fixed_cents);
    if let Some(p) = req.priority {
        active.priority = Set(p);
    }
    if let Some(v) = req.allowed_payment_methods {
        if v.is_empty() {
            active.allowed_payment_methods = Set(None);
        } else {
            payment_methods::validate_payment_methods_list(&v)?;
            active.allowed_payment_methods = Set(Some(payment_methods::vec_to_json_methods(v)?));
        }
    }
    active.updated_at = Set(now);

    let txn = state.db.begin().await?;
    let updated = active.update(&txn).await?;
    if let Some(ref ids) = req.product_ids {
        replace_promotion_products(&txn, promotion_id, ids).await?;
    }
    txn.commit().await?;

    Ok(Json(model_to_response(&state.db, updated).await?))
}

#[utoipa::path(
    delete,
    path = "/v1/sellers/me/promotions/{promotion_id}",
    responses(
        (status = 200, body = DeletePromotionResponse),
        (status = 401, body = crate::http::error::ProblemDetails),
        (status = 403, body = crate::http::error::ProblemDetails),
        (status = 404, body = crate::http::error::ProblemDetails),
        (status = 500, body = crate::http::error::ProblemDetails)
    ),
    security(("bearerAuth" = []))
)]
pub(crate) async fn delete_seller_promotion(
    headers: HeaderMap,
    Extension(state): Extension<AppState>,
    axum::extract::Path(promotion_id): axum::extract::Path<Uuid>,
) -> Result<Json<DeletePromotionResponse>, ApiError> {
    let (actor_sub, seller_id) = require_seller(&headers, &state).await?;
    let enforcer = casbin_authz::create_enforcer().await?;
    ensure_authorized(
        enforcer,
        &actor_sub,
        &promotion_obj(promotion_id),
        "delete",
        &actor_sub,
    )
    .await?;

    let deleted = promotion::Entity::delete_many()
        .filter(promotion::Column::Id.eq(promotion_id))
        .filter(promotion::Column::SellerId.eq(Some(seller_id)))
        .exec(&state.db)
        .await?;

    if deleted.rows_affected == 0 {
        return Err(ApiError::not_found("promotion not found"));
    }

    Ok(Json(DeletePromotionResponse { deleted: true }))
}

#[utoipa::path(
    post,
    path = "/v1/admin/promotions",
    request_body = CreatePromotionRequest,
    responses(
        (status = 200, body = PromotionResponse),
        (status = 400, body = crate::http::error::ProblemDetails),
        (status = 401, body = crate::http::error::ProblemDetails),
        (status = 403, body = crate::http::error::ProblemDetails),
        (status = 500, body = crate::http::error::ProblemDetails)
    ),
    security(("bearerAuth" = []))
)]
pub(crate) async fn create_admin_promotion(
    headers: HeaderMap,
    Extension(state): Extension<AppState>,
    Json(req): Json<CreatePromotionRequest>,
) -> Result<Json<PromotionResponse>, ApiError> {
    let (actor_sub, _admin_id) = require_admin(&headers, &state).await?;
    let enforcer = casbin_authz::create_enforcer().await?;
    ensure_authorized(
        enforcer,
        &actor_sub,
        &admin_promotions_collection_obj(),
        "create",
        &actor_sub,
    )
    .await?;

    validate_create(&req)?;
    assert_products_approved(&state.db, &req.product_ids).await?;

    let id = Uuid::new_v4();
    let now = Utc::now();
    let am = promotion::ActiveModel {
        id: Set(id),
        seller_id: Set(None),
        name: Set(req.name.trim().to_string()),
        status: Set(req.status.clone()),
        starts_at: Set(req.starts_at),
        ends_at: Set(req.ends_at),
        discount_kind: Set(req.discount_kind.clone()),
        discount_percent: Set(req.discount_percent),
        discount_fixed_cents: Set(req.discount_fixed_cents),
        priority: Set(req.priority),
        allowed_payment_methods: Set(payment_methods::opt_vec_to_json_methods(
            req.allowed_payment_methods.clone(),
        )?),
        created_at: Set(now),
        updated_at: Set(now),
    };

    let txn = state.db.begin().await?;
    promotion::Entity::insert(am).exec(&txn).await?;
    replace_promotion_products(&txn, id, &req.product_ids).await?;
    txn.commit().await?;

    let row = promotion::Entity::find_by_id(id)
        .one(&state.db)
        .await?
        .ok_or_else(|| ApiError::internal("promotion insert missing".to_string()))?;
    Ok(Json(model_to_response(&state.db, row).await?))
}

#[utoipa::path(
    get,
    path = "/v1/admin/promotions",
    responses(
        (status = 200, body = Vec<PromotionResponse>),
        (status = 401, body = crate::http::error::ProblemDetails),
        (status = 403, body = crate::http::error::ProblemDetails),
        (status = 500, body = crate::http::error::ProblemDetails)
    ),
    security(("bearerAuth" = []))
)]
pub(crate) async fn list_admin_promotions(
    headers: HeaderMap,
    Extension(state): Extension<AppState>,
) -> Result<Json<Vec<PromotionResponse>>, ApiError> {
    let (actor_sub, _admin_id) = require_admin(&headers, &state).await?;
    let enforcer = casbin_authz::create_enforcer().await?;
    ensure_authorized(
        enforcer,
        &actor_sub,
        &admin_promotions_collection_obj(),
        "read",
        &actor_sub,
    )
    .await?;

    let rows = promotion::Entity::find()
        .filter(promotion::Column::SellerId.is_null())
        .order_by_desc(promotion::Column::CreatedAt)
        .all(&state.db)
        .await?;

    let mut out = Vec::with_capacity(rows.len());
    for m in rows {
        out.push(model_to_response(&state.db, m).await?);
    }
    Ok(Json(out))
}

#[utoipa::path(
    get,
    path = "/v1/admin/promotions/{promotion_id}",
    responses(
        (status = 200, body = PromotionResponse),
        (status = 401, body = crate::http::error::ProblemDetails),
        (status = 403, body = crate::http::error::ProblemDetails),
        (status = 404, body = crate::http::error::ProblemDetails),
        (status = 500, body = crate::http::error::ProblemDetails)
    ),
    security(("bearerAuth" = []))
)]
pub(crate) async fn get_admin_promotion(
    headers: HeaderMap,
    Extension(state): Extension<AppState>,
    axum::extract::Path(promotion_id): axum::extract::Path<Uuid>,
) -> Result<Json<PromotionResponse>, ApiError> {
    let (actor_sub, _admin_id) = require_admin(&headers, &state).await?;
    let enforcer = casbin_authz::create_enforcer().await?;
    ensure_authorized(
        enforcer,
        &actor_sub,
        &admin_promotion_obj(promotion_id),
        "read",
        &actor_sub,
    )
    .await?;

    let row = promotion::Entity::find_by_id(promotion_id)
        .filter(promotion::Column::SellerId.is_null())
        .one(&state.db)
        .await?
        .ok_or_else(|| ApiError::not_found("promotion not found"))?;

    Ok(Json(model_to_response(&state.db, row).await?))
}

#[utoipa::path(
    patch,
    path = "/v1/admin/promotions/{promotion_id}",
    request_body = UpdatePromotionRequest,
    responses(
        (status = 200, body = PromotionResponse),
        (status = 400, body = crate::http::error::ProblemDetails),
        (status = 401, body = crate::http::error::ProblemDetails),
        (status = 403, body = crate::http::error::ProblemDetails),
        (status = 404, body = crate::http::error::ProblemDetails),
        (status = 500, body = crate::http::error::ProblemDetails)
    ),
    security(("bearerAuth" = []))
)]
pub(crate) async fn update_admin_promotion(
    headers: HeaderMap,
    Extension(state): Extension<AppState>,
    axum::extract::Path(promotion_id): axum::extract::Path<Uuid>,
    Json(req): Json<UpdatePromotionRequest>,
) -> Result<Json<PromotionResponse>, ApiError> {
    let (actor_sub, _admin_id) = require_admin(&headers, &state).await?;
    let enforcer = casbin_authz::create_enforcer().await?;
    ensure_authorized(
        enforcer,
        &actor_sub,
        &admin_promotion_obj(promotion_id),
        "update",
        &actor_sub,
    )
    .await?;

    let existing = promotion::Entity::find_by_id(promotion_id)
        .filter(promotion::Column::SellerId.is_null())
        .one(&state.db)
        .await?
        .ok_or_else(|| ApiError::not_found("promotion not found"))?;

    validate_update_patch(&req)?;
    if let Some(ref ids) = req.product_ids {
        assert_products_approved(&state.db, ids).await?;
    }

    let (starts_at, ends_at) = merged_time_window(&existing, &req)?;
    let (discount_kind, discount_percent, discount_fixed_cents) =
        merge_discount_update(&existing, &req)?;

    let now = Utc::now();
    let mut active: promotion::ActiveModel = existing.into_active_model();
    if let Some(n) = req.name {
        active.name = Set(n.trim().to_string());
    }
    if let Some(s) = req.status {
        active.status = Set(s);
    }
    active.starts_at = Set(starts_at);
    active.ends_at = Set(ends_at);
    active.discount_kind = Set(discount_kind);
    active.discount_percent = Set(discount_percent);
    active.discount_fixed_cents = Set(discount_fixed_cents);
    if let Some(p) = req.priority {
        active.priority = Set(p);
    }
    if let Some(v) = req.allowed_payment_methods {
        if v.is_empty() {
            active.allowed_payment_methods = Set(None);
        } else {
            payment_methods::validate_payment_methods_list(&v)?;
            active.allowed_payment_methods = Set(Some(payment_methods::vec_to_json_methods(v)?));
        }
    }
    active.updated_at = Set(now);

    let txn = state.db.begin().await?;
    let updated = active.update(&txn).await?;
    if let Some(ref ids) = req.product_ids {
        replace_promotion_products(&txn, promotion_id, ids).await?;
    }
    txn.commit().await?;

    Ok(Json(model_to_response(&state.db, updated).await?))
}

#[utoipa::path(
    delete,
    path = "/v1/admin/promotions/{promotion_id}",
    responses(
        (status = 200, body = DeletePromotionResponse),
        (status = 401, body = crate::http::error::ProblemDetails),
        (status = 403, body = crate::http::error::ProblemDetails),
        (status = 404, body = crate::http::error::ProblemDetails),
        (status = 500, body = crate::http::error::ProblemDetails)
    ),
    security(("bearerAuth" = []))
)]
pub(crate) async fn delete_admin_promotion(
    headers: HeaderMap,
    Extension(state): Extension<AppState>,
    axum::extract::Path(promotion_id): axum::extract::Path<Uuid>,
) -> Result<Json<DeletePromotionResponse>, ApiError> {
    let (actor_sub, _admin_id) = require_admin(&headers, &state).await?;
    let enforcer = casbin_authz::create_enforcer().await?;
    ensure_authorized(
        enforcer,
        &actor_sub,
        &admin_promotion_obj(promotion_id),
        "delete",
        &actor_sub,
    )
    .await?;

    let deleted = promotion::Entity::delete_many()
        .filter(promotion::Column::Id.eq(promotion_id))
        .filter(promotion::Column::SellerId.is_null())
        .exec(&state.db)
        .await?;

    if deleted.rows_affected == 0 {
        return Err(ApiError::not_found("promotion not found"));
    }

    Ok(Json(DeletePromotionResponse { deleted: true }))
}
