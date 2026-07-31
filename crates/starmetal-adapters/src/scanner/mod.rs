//! Outbound [`starmetal_core::supply_chain::Scanner`] implementations (ADR-0024).
//!
//! Each scanner is a self-contained, feature-gated module implementing the stable `Scanner` port
//! defined in `starmetal-core`. Wiring a scanner into the request pipeline is a later increment;
//! this module only provides the outbound clients themselves.

#[cfg(feature = "scanner-osv")]
mod osv;
#[cfg(feature = "scanner-osv")]
pub use osv::OsvScanner;
