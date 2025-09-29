# vc-demo
Verifiable Credentials

## Development

- Ensure Rust and Cargo are installed (https://www.rust-lang.org/tools/install).
- Run `cargo check` to verify the project compiles.

### Environment

- Copy `.env` and fill in the Auth0 values.
- `SESSION_SECRET` must resolve to at least 64 bytes. You can provide a base64-encoded 64-byte string (recommended) or a plain string of 64+ characters. The application will fall back to a SHA-512 derived key for shorter values but prints a warning, so use a strong secret in production.
- Sessions are stored server-side in memory. Restarting the application clears login state.*** End Patch
