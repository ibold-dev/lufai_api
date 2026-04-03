//! Shopping carts: one cart per customer, line items with product + quantity.

use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20260403000004_carts"
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
    r#"CREATE TABLE carts (
    id UUID PRIMARY KEY,
    customer_id UUID NOT NULL UNIQUE REFERENCES customers(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
)"#,
    r#"CREATE TABLE cart_items (
    id UUID PRIMARY KEY,
    cart_id UUID NOT NULL REFERENCES carts(id) ON DELETE CASCADE,
    product_id UUID NOT NULL REFERENCES products(id) ON DELETE CASCADE,
    quantity INT NOT NULL,
    CONSTRAINT cart_items_qty_positive CHECK (quantity > 0),
    CONSTRAINT cart_items_unique_product UNIQUE (cart_id, product_id)
)"#,
    "CREATE INDEX idx_cart_items_cart_id ON cart_items(cart_id)",
];

const DOWN_STATEMENTS: &[&str] = &[
    "DROP TABLE IF EXISTS cart_items",
    "DROP TABLE IF EXISTS carts",
];
