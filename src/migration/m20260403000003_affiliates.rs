//! Affiliates table and optional `customers.affiliate_id` (set at signup only).

use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20260403000003_affiliates"
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
    r#"CREATE TABLE affiliates (
    id UUID PRIMARY KEY,
    code TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT affiliates_code_len CHECK (char_length(code) >= 1 AND char_length(code) <= 32)
)"#,
    r#"ALTER TABLE customers ADD COLUMN affiliate_id UUID REFERENCES affiliates(id) ON DELETE SET NULL"#,
    "CREATE INDEX idx_customers_affiliate_id ON customers(affiliate_id)",
];

const DOWN_STATEMENTS: &[&str] = &[
    "ALTER TABLE customers DROP COLUMN IF EXISTS affiliate_id",
    "DROP TABLE IF EXISTS affiliates",
];
