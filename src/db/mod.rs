use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;

use crate::http::error::ApiError;

pub async fn try_create_pool() -> Result<Option<PgPool>, ApiError> {
    let database_url = match std::env::var("DATABASE_URL") {
        Ok(v) => v,
        Err(_) => return Ok(None),
    };

    let pool = PgPoolOptions::new()
        .max_connections(10)
        .connect(&database_url)
        .await
        .map_err(|e| ApiError::internal(format!("failed to connect db: {e}")))?;

    // Running migrations is idempotent: SQLx will track applied versions.
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .map_err(|e| ApiError::internal(format!("failed to run migrations: {e}")))?;

    Ok(Some(pool))
}

