#[cfg(feature = "pypi")]
pub mod pypi;

#[cfg(feature = "npm")]
pub mod npm;

#[cfg(feature = "cargo-registry")]
pub mod cargo;

#[cfg(feature = "hex")]
pub mod hex;

#[cfg(feature = "maven")]
pub mod maven;

#[cfg(feature = "rubygems")]
pub mod rubygems;

#[cfg(feature = "nuget")]
pub mod nuget;

#[cfg(feature = "pub")]
pub mod pubdev;
