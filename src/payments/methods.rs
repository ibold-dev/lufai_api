//! Payment method identifiers: electronic (online), cash on delivery, installment.

use std::collections::HashSet;

use crate::entity::{product, promotion};
use crate::http::error::ApiError;

pub const ELECTRONIC: &str = "electronic";
pub const CASH_ON_DELIVERY: &str = "cash_on_delivery";
pub const INSTALLMENT: &str = "installment";

/// Canonical ordering for stable JSON and intersections.
pub fn all_payment_methods() -> Vec<String> {
    vec![
        ELECTRONIC.to_string(),
        CASH_ON_DELIVERY.to_string(),
        INSTALLMENT.to_string(),
    ]
}

fn canonical_sort(methods: &mut [String]) {
    let order = [ELECTRONIC, CASH_ON_DELIVERY, INSTALLMENT];
    methods.sort_by_key(|m| {
        order
            .iter()
            .position(|&o| o == m.as_str())
            .unwrap_or(99)
    });
}

/// Validates a non-empty list of unique known method ids.
pub fn validate_payment_methods_list(methods: &[String]) -> Result<(), ApiError> {
    if methods.is_empty() {
        return Err(ApiError::bad_request(
            "allowed_payment_methods must not be empty",
        ));
    }
    let mut seen = HashSet::new();
    for s in methods {
        match s.as_str() {
            ELECTRONIC | CASH_ON_DELIVERY | INSTALLMENT => {}
            _ => return Err(ApiError::bad_request("invalid payment method")),
        }
        if !seen.insert(s.as_str()) {
            return Err(ApiError::bad_request("duplicate payment method"));
        }
    }
    Ok(())
}

pub fn product_effective_methods(p: &product::Model) -> Vec<String> {
    match &p.allowed_payment_methods {
        None => all_payment_methods(),
        Some(v) if v.is_empty() => all_payment_methods(),
        Some(v) => v.clone(),
    }
}

/// Product defaults, optionally overridden by an active promotion row.
pub fn line_effective_methods(p: &product::Model, promo: Option<&promotion::Model>) -> Vec<String> {
    let base = product_effective_methods(p);
    let Some(pr) = promo else {
        return base;
    };
    match &pr.allowed_payment_methods {
        None => base,
        Some(v) if v.is_empty() => base,
        Some(v) => v.clone(),
    }
}

/// Intersection of per-line method sets; empty intersection is an error at checkout.
pub fn intersect_line_methods(lines: &[Vec<String>]) -> Result<Vec<String>, ApiError> {
    if lines.is_empty() {
        return Err(ApiError::bad_request("no lines to compute payment methods"));
    }
    let mut acc: HashSet<String> = lines[0].iter().cloned().collect();
    for line in &lines[1..] {
        let s: HashSet<String> = line.iter().cloned().collect();
        acc = acc.intersection(&s).cloned().collect();
    }
    if acc.is_empty() {
        return Err(ApiError::bad_request(
            "items have no common allowed payment method",
        ));
    }
    let mut out: Vec<String> = acc.into_iter().collect();
    canonical_sort(&mut out);
    Ok(out)
}

pub fn order_allows_electronic(methods: &[String]) -> bool {
    methods.iter().any(|m| m == ELECTRONIC)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn intersect_requires_common_method() {
        let a = vec![ELECTRONIC.to_string(), CASH_ON_DELIVERY.to_string()];
        let b = vec![CASH_ON_DELIVERY.to_string(), INSTALLMENT.to_string()];
        let out = intersect_line_methods(&[a, b]).expect("intersect");
        assert_eq!(out, vec![CASH_ON_DELIVERY.to_string()]);
    }

    #[test]
    fn intersect_empty_is_error() {
        let a = vec![ELECTRONIC.to_string()];
        let b = vec![CASH_ON_DELIVERY.to_string()];
        assert!(intersect_line_methods(&[a, b]).is_err());
    }
}
