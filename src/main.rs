mod admin;
mod auth;
mod authz;
mod db;
mod entity;
mod migration;
mod http;
mod products;
mod orders;
mod payments;
mod state;
mod openapi;
mod cart;
mod catalog;
mod customers;
mod promotions;

use axum::extract::DefaultBodyLimit;
use axum::Extension;
use governor::middleware::NoOpMiddleware;
use http::error::ApiError;
use http::handlers::{healthz, v1_root};
use http::limits::DEFAULT_REQUEST_BODY_MAX;
use state::AppState;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::trace::TraceLayer;
use tower_governor::governor::GovernorConfig;
use tower_governor::key_extractor::PeerIpKeyExtractor;
use tower_governor::GovernorLayer;
use tower_http::cors::{Any, CorsLayer};
use tracing_subscriber::EnvFilter;
use utoipa_swagger_ui::SwaggerUi;
use utoipa::OpenApi;

use axum::http::header::{HeaderName, HeaderValue};

fn governor_secure_auth(
) -> GovernorLayer<PeerIpKeyExtractor, NoOpMiddleware, axum::body::Body> {
    GovernorLayer::new(Arc::new(
        GovernorConfig::<PeerIpKeyExtractor, NoOpMiddleware>::secure(),
    ))
}

fn governor_default_api(
) -> GovernorLayer<PeerIpKeyExtractor, NoOpMiddleware, axum::body::Body> {
    GovernorLayer::new(Arc::new(
        GovernorConfig::<PeerIpKeyExtractor, NoOpMiddleware>::default(),
    ))
}

#[tokio::main]
async fn main() -> Result<(), ApiError> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("info".parse().unwrap()))
        .init();

    // Check for CLI script commands
    let args: Vec<String> = std::env::args().collect();
    if args.len() >= 4 && args[1] == "seed-admin" {
        let email = &args[2];
        let password = &args[3];
        tracing::info!("Seeding admin account for {}...", email);

        let db = db::try_create_db().await?.expect("DATABASE_URL is not set");
        let password_hash = auth::password::hash_password(password)?;
        let now = chrono::Utc::now();
        let admin_id = uuid::Uuid::new_v4();

        let active = entity::admin::ActiveModel {
            id: sea_orm::Set(admin_id),
            email: sea_orm::Set(email.clone()),
            full_name: sea_orm::Set("Admin".to_string()),
            password_hash: sea_orm::Set(password_hash),
            created_at: sea_orm::Set(now),
            updated_at: sea_orm::Set(now),
        };

        use sea_orm::EntityTrait;
        match entity::admin::Entity::insert(active).exec(&db).await {
            Ok(_) => {
                tracing::info!("Successfully created admin with ID {}", admin_id);
                std::process::exit(0);
            }
            Err(e) => {
                tracing::error!("Failed to create admin (does it already exist?): {}", e);
                std::process::exit(1);
            }
        }
    }

    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(3000);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = TcpListener::bind(addr)
        .await
        .map_err(|e| ApiError::internal(format!("failed to bind: {e}")))?;

    let db = db::try_create_db()
        .await?
        .ok_or_else(|| ApiError::internal("DATABASE_URL is not set".to_string()))?;
    let state = AppState::from_db(db)?;

    let v1_business = axum::Router::new()
        .merge(catalog::routes::routes())
        .merge(admin::routes::routes())
        .merge(products::routes::routes())
        .merge(promotions::routes::routes())
        .merge(orders::routes::routes())
        .merge(cart::routes::routes())
        .merge(customers::routes::routes())
        .merge(payments::routes::routes())
        .layer(governor_default_api());

    let swagger_ui = SwaggerUi::new("/v1/docs")
        .url("/v1/openapi.json", openapi::ApiDoc::openapi());
    let swagger_router: axum::Router<()> = axum::Router::from(swagger_ui);

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app = axum::Router::new()
        .route("/healthz", axum::routing::get(healthz))
        .route("/v1", axum::routing::get(v1_root))
        .nest("/v1", auth::routes::routes().layer(governor_secure_auth()))
        .nest("/v1", v1_business)
        .merge(swagger_router)
        .fallback(not_found)
        .layer(
            SetResponseHeaderLayer::if_not_present(
                HeaderName::from_static("x-content-type-options"),
                HeaderValue::from_static("nosniff"),
            ),
        )
        .layer(
            SetResponseHeaderLayer::if_not_present(
                HeaderName::from_static("x-frame-options"),
                HeaderValue::from_static("DENY"),
            ),
        )
        .layer(
            SetResponseHeaderLayer::if_not_present(
                HeaderName::from_static("referrer-policy"),
                HeaderValue::from_static("strict-origin-when-cross-origin"),
            ),
        )
        .layer(DefaultBodyLimit::max(DEFAULT_REQUEST_BODY_MAX))
        .layer(Extension(state))
        .layer(TraceLayer::new_for_http())
        .layer(cors);

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
