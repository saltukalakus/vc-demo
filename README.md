# vc-demo
Verifiable Credentials

## Development

- Ensure Rust and Cargo are installed (https://www.rust-lang.org/tools/install).
- Run `cargo check` to verify the project compiles.

### Environment

- Copy `.env` and fill in the Auth0 values.
- `SESSION_SECRET` must resolve to at least 64 bytes. You can provide a base64-encoded 64-byte string (recommended) or a plain string of 64+ characters. The application will fall back to a SHA-512 derived key for shorter values but prints a warning, so use a strong secret in production.
- `ISSUER_JWK` should contain an Ed25519 private JWK (JSON string). If omitted, the server will generate an ephemeral Ed25519 key on startup; this is handy for local development but unsuitable for production because the key rotates on every restart.
- Optional overrides:
	- `ISSUER_DID` replaces the derived `did:key` identifier used in the credential issuer field.
	- `ISSUER_VERIFICATION_METHOD` replaces the default verification method URI. If omitted, a `did:key` verification method URL is generated and also applied as the JWK `kid`.
- Sessions are stored server-side in memory. Restarting the application clears login state.

### Running locally

1. Start the server:

	 ```bash
	 cargo run
	 ```

2. Navigate to <http://localhost:8080>, authenticate with Auth0, then visit `/issue-vc` to receive a SpruceID-signed Verifiable Credential containing your ID token.
3. To load a credential into a digital wallet, open `/issue-vc/qr`. The page renders a scannable QR code plus the raw payload so you can transfer the credential without downloading JSON manually.

### Issuance details

- Credentials are issued using `spruceid/ssi` with the Ed25519 cryptographic suite selected automatically from the configured issuer key.
- After signing, each credential is verified before being returned, providing immediate assurance that the generated proof is valid.
- The credential payload includes:
	- Contexts: the W3C VC v1 context plus an Auth0-specific extension.
	- Types: `VerifiableCredential` and `Auth0IdTokenCredential`.
	- Subject: a unique UUID identifier and the raw ID token that Auth0 returned during login.
- The QR endpoint embeds the full signed credential (minified JSON) in the code. Clients decoding the QR can store the credential directly without performing an additional network fetch.
