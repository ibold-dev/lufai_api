//! SeaORM migrations: schema changes live here (`sea-orm-cli migrate generate` for new revisions).

mod m20260403000000_init;

use sea_orm_migration::prelude::*;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![Box::new(m20260403000000_init::Migration)]
    }
}
