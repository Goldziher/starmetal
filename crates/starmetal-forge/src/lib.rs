//! Forge backends for the Starmetal dependency-update engine.
//!
//! A forge is a hosted git platform (GitHub, GitLab, Gitea, ...) that can list a repository's
//! files, read manifest content, and open pull requests. This crate provides adapters that
//! implement [`starmetal_update_core::ports::Forge`] against those platforms so the update
//! engine can propose dependency bumps without knowing which platform hosts a given repository.
//!
//! Backends are feature-gated; the `github` feature (enabled by default) provides
//! [`GithubForge`], built on [`octocrab`].

#[cfg(feature = "github")]
mod github;

#[cfg(feature = "github")]
pub use github::GithubForge;
