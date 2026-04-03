//! Product / promotion payment eligibility and per-order snapshot.

use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20260403000007_payment_methods"
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
    r#"ALTER TABLE products ADD COLUMN allowed_payment_methods JSONB"#,
    r#"ALTER TABLE promotions ADD COLUMN allowed_payment_methods JSONB"#,
    r#"ALTER TABLE orders ADD COLUMN allowed_payment_methods JSONB NOT NULL DEFAULT '["electronic","cash_on_delivery","installment"]'::jsonb"#,
];

const DOWN_STATEMENTS: &[&str] = &[
    "ALTER TABLE orders DROP COLUMN IF EXISTS allowed_payment_methods",
    "ALTER TABLE promotions DROP COLUMN IF EXISTS allowed_payment_methods",
    "ALTER TABLE products DROP COLUMN IF EXISTS allowed_payment_methods",
];
