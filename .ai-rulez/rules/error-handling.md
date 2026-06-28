---
priority: high
---

# Error Handling

- Each crate converts external errors into `StarmetalError` at the boundary using `From` impls or `.map_err()`.
- HTTP handlers map `StarmetalError` variants to appropriate status codes.
- Use `thiserror` for all error enums.
- Never use `.unwrap()` or `.expect()` in library crates. The CLI binary may use `.unwrap_or_else()` with proper error messages for startup code only.
