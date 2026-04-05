//! Nullable seller password; login codes for sellers/affiliates; affiliate email for login.

use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20260403000009_seller_affiliate_login_codes"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let conn = manager.get_connection();
        for sql in UP_STATEMENTS {
            conn.execute_unprepared(sql).await?;
        }
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let conn = manager.get_connection();
        for sql in DOWN_STATEMENTS {
            conn.execute_unprepared(sql).await?;
        }
        Ok(())
    }
}

const UP_STATEMENTS: &[&str] = &[
    "ALTER TABLE sellers ALTER COLUMN password_hash DROP NOT NULL",
    r#"ALTER TABLE sellers ADD COLUMN IF NOT EXISTS login_code_hash TEXT"#,
    r#"ALTER TABLE sellers ADD COLUMN IF NOT EXISTS login_revoked_at TIMESTAMPTZ"#,
    r#"ALTER TABLE affiliates ADD COLUMN IF NOT EXISTS email TEXT"#,
    "CREATE UNIQUE INDEX IF NOT EXISTS uq_affiliates_email ON affiliates(email) WHERE email IS NOT NULL",
    r#"ALTER TABLE affiliates ADD COLUMN IF NOT EXISTS login_code_hash TEXT"#,
    r#"ALTER TABLE affiliates ADD COLUMN IF NOT EXISTS login_revoked_at TIMESTAMPTZ"#,
];

const DOWN_STATEMENTS: &[&str] = &[
    "ALTER TABLE affiliates DROP COLUMN IF EXISTS login_revoked_at",
    "ALTER TABLE affiliates DROP COLUMN IF EXISTS login_code_hash",
    "DROP INDEX IF EXISTS uq_affiliates_email",
    "ALTER TABLE affiliates DROP COLUMN IF EXISTS email",
    "ALTER TABLE sellers DROP COLUMN IF EXISTS login_revoked_at",
    "ALTER TABLE sellers DROP COLUMN IF EXISTS login_code_hash",
];
