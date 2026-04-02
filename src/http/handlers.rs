use axum::Json;
use serde::Serialize;

use super::error::ApiError;

#[utoipa::path(
    get,
    path = "/healthz",
    responses(
        (status = 200, body = HealthzResponse),
        (status = 500, body = crate::http::error::ProblemDetails)
    )
)]
pub async fn healthz() -> Result<Json<HealthzResponse>, ApiError> {
    Ok(Json(HealthzResponse { status: "ok" }))
}

#[utoipa::path(
    get,
    path = "/v1",
    responses(
        (status = 200, body = V1RootResponse),
        (status = 500, body = crate::http::error::ProblemDetails)
    )
)]
pub async fn v1_root() -> Result<Json<V1RootResponse>, ApiError> {
    Ok(Json(V1RootResponse {
        status: "ok",
        version: "v1",
    }))
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct HealthzResponse {
    pub status: &'static str,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct V1RootResponse {
    pub status: &'static str,
    pub version: &'static str,
}
