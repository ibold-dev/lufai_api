//! Nullable `password_hash` for Google-only customers; `google_sub` for Google account id.

use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20260403000001_customer_google_auth"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let conn = manager.get_connection();
        conn.execute_unprepared(
            r#"ALTER TABLE customers ALTER COLUMN password_hash DROP NOT NULL"#,
        )
        .await?;
        conn.execute_unprepared(r#"ALTER TABLE customers ADD COLUMN google_sub TEXT UNIQUE"#)
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let conn = manager.get_connection();
        conn.execute_unprepared(r#"ALTER TABLE customers DROP COLUMN IF EXISTS google_sub"#)
            .await?;
        // Cannot safely restore NOT NULL on password_hash if any NULL rows exist.
        Ok(())
    }
}
