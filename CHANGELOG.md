# Changelog

## 0.3.0 - Unreleased

### Security

- Bound TypeScript request, response, and error bodies.
- Require an explicit proxy path policy and default to read-only HTTP methods.
- Reject provider base-path traversal and cross-origin redirects.
- Remove API keys from command-line arguments in favor of interactive or standard-input entry.
- Prefer the native OS credential store for new vault master keys, with a secure file fallback.
- Add per-subject Remote MCP token-bucket rate limiting.
- Add Redis-backed cross-instance MCP session recovery, identity binding, and rate-limit state.

### Changed

- Standardize short-lived CLI JSON output as `{ "ok": ..., "data"|"error": ... }`.
- Report active, expiring, expired, and unauthenticated states accurately.
- Add Rust, MSRV, macOS, coverage, audit, and package CI gates.
- Update the TypeScript package contract to Node.js 20 or newer.
- Use pooled WAL-mode SQLite connections for concurrent broker workloads.
- Add filtered, machine-readable audit event inspection commands.
- Allow administrators to pre-provision upstream credentials for an exact Remote principal/tenant.
