---
priority: high
---

# Feature Flags

- All protocol adapters are gated behind feature flags in `starmetal-adapters`.
- All storage backends are gated behind feature flags in `starmetal-storage`.
- Feature flags are additive — combining features must never break builds.
- Use `#[cfg(feature = "...")]` on modules, not on individual functions.
- When adding a new adapter or backend, add corresponding feature flags and update `starmetal-cli`'s `full` feature.
