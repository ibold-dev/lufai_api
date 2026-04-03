//! Add `full_name` to customers, sellers, and admins.

use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20260403000002_full_names"
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
    r#"ALTER TABLE customers ADD COLUMN full_name TEXT NOT NULL DEFAULT ''"#,
    r#"ALTER TABLE sellers ADD COLUMN full_name TEXT NOT NULL DEFAULT ''"#,
    r#"ALTER TABLE admins ADD COLUMN full_name TEXT NOT NULL DEFAULT ''"#,
];

const DOWN_STATEMENTS: &[&str] = &[
    "ALTER TABLE customers DROP COLUMN IF EXISTS full_name",
    "ALTER TABLE sellers DROP COLUMN IF EXISTS full_name",
    "ALTER TABLE admins DROP COLUMN IF EXISTS full_name",
];
