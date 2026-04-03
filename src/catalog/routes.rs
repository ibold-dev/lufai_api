//! Public product browse/detail. Only `status = approved` rows are returned.

use axum::{
    extract::{Extension, Query},
    routing::get,
    Json, Router,
};
use sea_orm::{
    sea_query::Expr, ColumnTrait, Condition, EntityTrait, PaginatorTrait, QueryFilter, QueryOrder,
    QuerySelect,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    entity::product,
    http::error::ApiError,
    http::limits::{
        DEFAULT_CATALOG_PAGE_SIZE, MAX_CATALOG_PAGE_SIZE, MAX_CATALOG_SEARCH_LEN,
    },
    products::routes::{load_images_by_product_ids, model_to_response, ProductResponse},
    state::AppState,
};

pub fn routes() -> Router {
    Router::new()
        .route("/products", get(list_catalog_products))
        .route("/products/{product_id}", get(get_catalog_product))
}

const APPROVED: &str = "approved";

#[derive(Debug, Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub struct CatalogListQuery {
    /// Max items to return (default 20, max 50).
    pub limit: Option<u32>,
    /// Offset for pagination.
    #[serde(default)]
    pub offset: u32,
    /// Case-insensitive substring match on title (`%` / `_` not allowed in input).
    pub q: Option<String>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct CatalogProductsPage {
    pub items: Vec<ProductResponse>,
    pub total: u64,
    pub limit: u32,
    pub offset: u32,
}

fn normalize_limit(limit: Option<u32>) -> u32 {
    let raw = limit.unwrap_or(DEFAULT_CATALOG_PAGE_SIZE);
    raw.clamp(1, MAX_CATALOG_PAGE_SIZE)
}

/// Strips LIKE wildcards and bounds length so `ILIKE` patterns stay safe.
fn catalog_search_fragment(q: &str) -> Option<String> {
    let t: String = q
        .trim()
        .chars()
        .filter(|c| *c != '%' && *c != '_' && *c != '\\')
        .take(MAX_CATALOG_SEARCH_LEN)
        .collect();
    if t.is_empty() {
        None
    } else {
        Some(t)
    }
}

#[utoipa::path(
    get,
    path = "/v1/products",
    params(CatalogListQuery),
    responses(
        (status = 200, body = CatalogProductsPage),
        (status = 400, body = crate::http::error::ProblemDetails),
        (status = 500, body = crate::http::error::ProblemDetails)
    )
)]
pub(crate) async fn list_catalog_products(
    Extension(state): Extension<AppState>,
    Query(q): Query<CatalogListQuery>,
) -> Result<Json<CatalogProductsPage>, ApiError> {
    let limit = normalize_limit(q.limit);
    let offset = q.offset;
    let search = q.q.as_deref().and_then(catalog_search_fragment);

    let mut filter = Condition::all().add(product::Column::Status.eq(APPROVED));
    if let Some(ref frag) = search {
        let pattern = format!("%{}%", frag);
        filter = filter.add(Expr::cust_with_values("products.title ILIKE ?", vec![pattern]));
    }

    let total = product::Entity::find()
        .filter(filter.clone())
        .count(&state.db)
        .await?;

    let rows = product::Entity::find()
        .filter(filter)
        .order_by_desc(product::Column::UpdatedAt)
        .limit(u64::from(limit))
        .offset(u64::from(offset))
        .all(&state.db)
        .await?;

    let ids: Vec<Uuid> = rows.iter().map(|r| r.id).collect();
    let img_map = load_images_by_product_ids(&state.db, &ids).await?;
    let items = rows
        .into_iter()
        .map(|m| {
            let imgs = img_map.get(&m.id).cloned().unwrap_or_default();
            model_to_response(m, imgs)
        })
        .collect();

    Ok(Json(CatalogProductsPage {
        items,
        total,
        limit,
        offset,
    }))
}

#[utoipa::path(
    get,
    path = "/v1/products/{product_id}",
    params(
        ("product_id" = Uuid, Path, description = "Product id")
    ),
    responses(
        (status = 200, body = ProductResponse),
        (status = 404, body = crate::http::error::ProblemDetails),
        (status = 500, body = crate::http::error::ProblemDetails)
    )
)]
pub(crate) async fn get_catalog_product(
    Extension(state): Extension<AppState>,
    axum::extract::Path(product_id): axum::extract::Path<Uuid>,
) -> Result<Json<ProductResponse>, ApiError> {
    let m = product::Entity::find_by_id(product_id)
        .filter(product::Column::Status.eq(APPROVED))
        .one(&state.db)
        .await?
        .ok_or_else(|| ApiError::not_found("product not found"))?;
    let images = load_images_by_product_ids(&state.db, &[product_id])
        .await?
        .remove(&product_id)
        .unwrap_or_default();
    Ok(Json(model_to_response(m, images)))
}
