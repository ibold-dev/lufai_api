use sea_orm::{DatabaseConnection, DbErr, RuntimeErr, SqlxPostgresConnector};
use sea_orm_migration::MigratorTrait;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;

use crate::http::error::ApiError;
use crate::migration::Migrator;

/// Postgres unique violation (SQLSTATE `23505`).
pub fn db_err_is_unique_violation(err: &DbErr) -> bool {
    fn sqlx_is_unique(e: &sqlx::Error) -> bool {
        if let sqlx::Error::Database(db) = e {
            return db.code().as_deref() == Some("23505");
        }
        false
    }

    match err {
        DbErr::Exec(RuntimeErr::SqlxError(e)) | DbErr::Query(RuntimeErr::SqlxError(e)) => {
            sqlx_is_unique(e)
        }
        _ => false,
    }
}

/// Builds a `sqlx` pool, runs SeaORM migrations, then wraps the pool as a SeaORM connection.
pub async fn try_create_db() -> Result<Option<DatabaseConnection>, ApiError> {
    let database_url = match std::env::var("DATABASE_URL") {
        Ok(v) => v,
        Err(_) => return Ok(None),
    };

    let pool: PgPool = PgPoolOptions::new()
        .max_connections(10)
        .connect(&database_url)
        .await
        .map_err(|e| ApiError::internal(format!("failed to connect db: {e}")))?;

    let db = SqlxPostgresConnector::from_sqlx_postgres_pool(pool);
    Migrator::up(&db, None)
        .await
        .map_err(|e| ApiError::internal(format!("failed to run migrations: {e}")))?;

    Ok(Some(db))
}
