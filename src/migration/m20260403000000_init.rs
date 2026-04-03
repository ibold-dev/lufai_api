//! Initial marketplace schema (customers, sellers, products, orders, payments, idempotency, webhooks).

use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20260403000000_init"
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
    r#"CREATE TABLE customers (
    id UUID PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    phone TEXT,
    address JSONB,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
)"#,
    r#"CREATE TABLE sellers (
    id UUID PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
)"#,
    r#"CREATE TABLE admins (
    id UUID PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
)"#,
    r#"CREATE TABLE products (
    id UUID PRIMARY KEY,
    seller_id UUID NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    price_cents BIGINT NOT NULL,
    currency TEXT NOT NULL,
    dimensions JSONB,
    status TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
)"#,
    "CREATE INDEX idx_products_seller_id ON products(seller_id)",
    "CREATE INDEX idx_products_status ON products(status)",
    r#"CREATE TABLE orders (
    id UUID PRIMARY KEY,
    customer_id UUID NOT NULL,
    status TEXT NOT NULL,
    currency TEXT NOT NULL,
    subtotal_cents BIGINT NOT NULL,
    shipping_cents BIGINT NOT NULL,
    tax_cents BIGINT NOT NULL,
    total_cents BIGINT NOT NULL,
    delivery_address JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
)"#,
    "CREATE INDEX idx_orders_customer_id ON orders(customer_id)",
    "CREATE INDEX idx_orders_status ON orders(status)",
    r#"CREATE TABLE order_items (
    id UUID PRIMARY KEY,
    order_id UUID NOT NULL,
    product_id UUID NOT NULL,
    unit_price_cents BIGINT NOT NULL,
    quantity INT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
)"#,
    "CREATE INDEX idx_order_items_order_id ON order_items(order_id)",
    r#"CREATE TABLE payment_attempts (
    id UUID PRIMARY KEY,
    order_id UUID NOT NULL,
    provider TEXT NOT NULL,
    paystack_reference TEXT NOT NULL UNIQUE,
    amount_cents BIGINT NOT NULL,
    currency TEXT NOT NULL,
    status TEXT NOT NULL,
    raw_payload JSONB,
    paid_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
)"#,
    "CREATE INDEX idx_payment_attempts_order_id ON payment_attempts(order_id)",
    r#"CREATE TABLE customer_order_idempotency (
    id UUID PRIMARY KEY,
    customer_id UUID NOT NULL,
    idempotency_key TEXT NOT NULL,
    order_id UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
)"#,
    "CREATE UNIQUE INDEX uq_customer_order_idempotency_key ON customer_order_idempotency(customer_id, idempotency_key)",
    r#"CREATE TABLE order_payment_idempotency (
    id UUID PRIMARY KEY,
    order_id UUID NOT NULL,
    idempotency_key TEXT NOT NULL,
    payment_attempt_id UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
)"#,
    "CREATE UNIQUE INDEX uq_order_payment_idempotency_key ON order_payment_idempotency(order_id, idempotency_key)",
    r#"CREATE TABLE webhook_events (
    id UUID PRIMARY KEY,
    provider TEXT NOT NULL,
    event_type TEXT NOT NULL,
    reference TEXT,
    raw_payload JSONB NOT NULL,
    received_at TIMESTAMPTZ NOT NULL,
    processed_at TIMESTAMPTZ
)"#,
    "CREATE INDEX idx_webhook_events_reference ON webhook_events(reference)",
];

const DOWN_STATEMENTS: &[&str] = &[
    "DROP TABLE IF EXISTS webhook_events",
    "DROP TABLE IF EXISTS order_payment_idempotency",
    "DROP TABLE IF EXISTS customer_order_idempotency",
    "DROP TABLE IF EXISTS payment_attempts",
    "DROP TABLE IF EXISTS order_items",
    "DROP TABLE IF EXISTS orders",
    "DROP TABLE IF EXISTS products",
    "DROP TABLE IF EXISTS admins",
    "DROP TABLE IF EXISTS sellers",
    "DROP TABLE IF EXISTS customers",
];
