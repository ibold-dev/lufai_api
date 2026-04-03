//! Promotions (campaigns) and discounted line pricing on `order_items`.

use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20260403000006_promotions"
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
    r#"CREATE TABLE promotions (
    id UUID PRIMARY KEY,
    seller_id UUID REFERENCES sellers(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    status TEXT NOT NULL,
    starts_at TIMESTAMPTZ NOT NULL,
    ends_at TIMESTAMPTZ NOT NULL,
    discount_kind TEXT NOT NULL,
    discount_percent INT,
    discount_fixed_cents BIGINT,
    priority INT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT promotions_time_order CHECK (ends_at > starts_at),
    CONSTRAINT promotions_discount_percent_range CHECK (discount_percent IS NULL OR (discount_percent >= 1 AND discount_percent <= 100)),
    CONSTRAINT promotions_discount_fixed_nonneg CHECK (discount_fixed_cents IS NULL OR discount_fixed_cents >= 0),
    CONSTRAINT promotions_discount_kind CHECK (
        (discount_kind = 'percent' AND discount_percent IS NOT NULL AND discount_fixed_cents IS NULL)
        OR (discount_kind = 'fixed_unit' AND discount_fixed_cents IS NOT NULL AND discount_percent IS NULL)
    )
)"#,
    "CREATE INDEX idx_promotions_seller_id ON promotions(seller_id)",
    "CREATE INDEX idx_promotions_status ON promotions(status)",
    r#"CREATE TABLE promotion_products (
    promotion_id UUID NOT NULL REFERENCES promotions(id) ON DELETE CASCADE,
    product_id UUID NOT NULL REFERENCES products(id) ON DELETE CASCADE,
    PRIMARY KEY (promotion_id, product_id)
)"#,
    "CREATE INDEX idx_promotion_products_product_id ON promotion_products(product_id)",
    r#"ALTER TABLE order_items ADD COLUMN list_unit_price_cents BIGINT"#,
    r#"UPDATE order_items SET list_unit_price_cents = unit_price_cents"#,
    r#"ALTER TABLE order_items ALTER COLUMN list_unit_price_cents SET NOT NULL"#,
    r#"ALTER TABLE order_items ADD COLUMN promotion_id UUID REFERENCES promotions(id) ON DELETE SET NULL"#,
];

const DOWN_STATEMENTS: &[&str] = &[
    "ALTER TABLE order_items DROP COLUMN IF EXISTS promotion_id",
    "ALTER TABLE order_items DROP COLUMN IF EXISTS list_unit_price_cents",
    "DROP TABLE IF EXISTS promotion_products",
    "DROP TABLE IF EXISTS promotions",
];
