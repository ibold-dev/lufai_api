//! Customer-chosen non-Paystack flows: COD confirmation and installment plan snapshot.

use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20260403000008_order_payment_flows"
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
    "ALTER TABLE orders ADD COLUMN payment_channel TEXT",
    "ALTER TABLE orders ADD COLUMN installment_plan JSONB",
    r#"CREATE TABLE order_payment_flow_idempotency (
    id UUID PRIMARY KEY,
    order_id UUID NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
    customer_id UUID NOT NULL REFERENCES customers(id),
    flow_kind TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT uq_order_payment_flow_idem UNIQUE (order_id, flow_kind, idempotency_key)
)"#,
    "CREATE INDEX idx_order_payment_flow_order_id ON order_payment_flow_idempotency(order_id)",
];

const DOWN_STATEMENTS: &[&str] = &[
    "DROP TABLE IF EXISTS order_payment_flow_idempotency",
    "ALTER TABLE orders DROP COLUMN IF EXISTS installment_plan",
    "ALTER TABLE orders DROP COLUMN IF EXISTS payment_channel",
];
