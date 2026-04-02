mod auth;
mod authz;
mod db;
mod http;
mod products;
mod orders;
mod payments;
mod state;
mod openapi;

use axum::Extension;
use http::error::ApiError;
use http::handlers::{healthz, v1_root};
use state::AppState;
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tower_http::trace::TraceLayer;
use tracing_subscriber::EnvFilter;
use utoipa_swagger_ui::SwaggerUi;
use utoipa::OpenApi;

#[tokio::main]
async fn main() -> Result<(), ApiError> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("info".parse().unwrap()))
        .init();

    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(3000);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = TcpListener::bind(addr)
        .await
        .map_err(|e| ApiError::internal(format!("failed to bind: {e}")))?;

    let pool = db::try_create_pool()
        .await?
        .ok_or_else(|| ApiError::internal("DATABASE_URL is not set".to_string()))?;
    let state = AppState::from_pool(pool)?;

    let app = axum::Router::new()
        .route("/healthz", axum::routing::get(healthz))
        .route("/v1", axum::routing::get(v1_root))
        .nest("/v1", auth::routes::routes())
        .nest("/v1", products::routes::routes())
        .nest("/v1", orders::routes::routes())
        .nest("/v1", payments::routes::routes())
        .fallback(not_found)
        .layer(Extension(state))
        .layer(TraceLayer::new_for_http());

    let swagger_ui = SwaggerUi::new("/v1/docs/{_:.*}")
        .url("/v1/openapi.json", openapi::ApiDoc::openapi());
    let swagger_router: axum::Router<()> = axum::Router::from(swagger_ui);
    let app = app.merge(swagger_router);

    tracing::info!("listening on http://{addr}");

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
        .await
        .map_err(|e| ApiError::internal(format!("server error: {e}")))?;

    Ok(())
}

async fn not_found() -> ApiError {
    ApiError::not_found("route not found")
}
