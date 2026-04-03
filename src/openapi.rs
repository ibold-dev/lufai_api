use utoipa::{openapi::ComponentsBuilder, Modify, OpenApi};

use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};

/// Adds JWT bearer auth security scheme to generated OpenAPI.
struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let bearer_scheme = SecurityScheme::Http(
            HttpBuilder::new()
                .scheme(HttpAuthScheme::Bearer)
                .bearer_format("JWT")
                .build(),
        );

        if let Some(components) = openapi.components.as_mut() {
            components
                .security_schemes
                .insert("bearerAuth".to_string(), bearer_scheme);
            return;
        }

        openapi.components = Some(
            ComponentsBuilder::new()
                .security_scheme("bearerAuth", bearer_scheme)
                .build(),
        );
    }
}

/// OpenAPI specification for the furniture marketplace API.
///
/// This is generated at build time using `utoipa` and exposed via `/v1/openapi.json`.
#[derive(OpenApi)]
#[openapi(
    modifiers(&SecurityAddon),
    paths(
        crate::http::handlers::healthz,
        crate::http::handlers::v1_root,
        crate::auth::routes::customer_register,
        crate::auth::routes::customer_login,
        crate::auth::routes::customer_google_sign_in,
        crate::auth::routes::seller_login,
        crate::auth::routes::admin_login,
        crate::products::routes::create_product,
        crate::products::routes::list_my_products,
        crate::products::routes::update_product,
        crate::products::routes::delete_product,
        crate::products::routes::list_pending_products,
        crate::products::routes::approve_product,
        crate::products::routes::reject_product,
        crate::orders::routes::create_order,
        crate::orders::routes::get_order,
        crate::cart::routes::get_cart,
        crate::cart::routes::put_cart_item,
        crate::cart::routes::delete_cart_item,
        crate::cart::routes::checkout_cart,
        crate::orders::routes::initialize_paystack,
        crate::payments::routes::paystack_webhook,
        crate::promotions::routes::create_seller_promotion,
        crate::promotions::routes::list_seller_promotions,
        crate::promotions::routes::get_seller_promotion,
        crate::promotions::routes::update_seller_promotion,
        crate::promotions::routes::delete_seller_promotion,
        crate::promotions::routes::create_admin_promotion,
        crate::promotions::routes::list_admin_promotions,
        crate::promotions::routes::get_admin_promotion,
        crate::promotions::routes::update_admin_promotion,
        crate::promotions::routes::delete_admin_promotion
    )
)]
pub struct ApiDoc;

