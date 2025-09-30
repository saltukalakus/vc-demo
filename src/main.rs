use axum::{
    extract::Query,
    http::StatusCode,
    response::{Html, IntoResponse, Redirect},
    routing::get,
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use dotenv::dotenv;
use openidconnect::{
    core::{CoreClient, CoreProviderMetadata, CoreResponseType},
    reqwest::async_http_client,
    AuthenticationFlow, AuthorizationCode, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce,
    PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope, TokenResponse,
};
use qrcode::{render::svg, QrCode};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha512};
use ssi::dids::DIDKey;
use ssi::json_ld::IriBuf;
use ssi::{
    claims::{
        data_integrity::{AnySuite, CryptographicSuite, ProofOptions},
        vc::v1::JsonCredential,
        VerificationParameters,
    },
    dids::{AnyDidMethod, VerificationMethodDIDResolver},
    jwk::{Algorithm, JWK},
    verification_methods::{AnyMethod, ProofPurpose, ReferenceOrOwned, SingleSecretSigner},
    xsd::DateTime,
};
use std::{env, sync::Arc};
use tokio::{net::TcpListener, sync::OnceCell};
use tower_sessions::{cookie::Key, MemoryStore, Session, SessionManagerLayer};
use uuid::Uuid;

// Shared OpenID client in app state
static OIDC_CLIENT: OnceCell<CoreClient> = OnceCell::const_new();
static ISSUER_CONFIG: OnceCell<IssuerConfig> = OnceCell::const_new();

#[derive(Deserialize)]
struct CallbackParams {
    code: String,
    state: String,
}

#[derive(Clone, Debug)]
struct IssuerConfig {
    jwk: Arc<JWK>,
    issuer: String,
    verification_method: String,
}

#[tokio::main]
async fn main() {
    dotenv().ok();

    // Discover Auth0 metadata
    let domain = env::var("AUTH0_DOMAIN").unwrap();
    let issuer = IssuerUrl::new(format!("https://{}/", domain)).unwrap();
    let meta = CoreProviderMetadata::discover_async(issuer, async_http_client)
        .await
        .unwrap();

    // Build OIDC client
    let client = CoreClient::from_provider_metadata(
        meta,
        ClientId::new(env::var("AUTH0_CLIENT_ID").unwrap()),
        Some(ClientSecret::new(env::var("AUTH0_CLIENT_SECRET").unwrap())),
    )
    .set_redirect_uri(RedirectUrl::new(env::var("AUTH0_REDIRECT_URL").unwrap()).unwrap());

    OIDC_CLIENT.set(client).unwrap();

    let issuer_config = load_issuer_config();
    ISSUER_CONFIG
        .set(issuer_config)
        .expect("ISSUER_CONFIG should only be initialized once");

    // Session middleware
    let secret_bytes = derive_session_secret();
    let key = Key::try_from(secret_bytes.as_slice())
        .expect("SESSION_SECRET must resolve to at least 64 bytes");
    let store = MemoryStore::default();
    let session_layer = SessionManagerLayer::new(store)
        .with_private(key)
        .with_secure(false);

    // Build the router
    let app = Router::new()
        .route("/", get(index))
        .route("/login", get(login))
        .route("/callback", get(callback))
        .route("/issue-vc", get(issue_vc))
        .route("/issue-vc/qr", get(issue_vc_qr))
        .layer(session_layer);

    println!("Listening on http://localhost:8080");
    let listener = TcpListener::bind("0.0.0.0:8080").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

// Public landing page
async fn index(session: Session) -> impl IntoResponse {
    let logged_in = session
        .get::<String>("id_token")
        .await
        .map(|value| value.is_some())
        .unwrap_or_else(|err| {
            eprintln!("Failed to read id_token from session: {err}");
            false
        });
    let html = if logged_in {
        r#"<h2>Authenticated</h2>
           <a href="/issue-vc">Issue VC</a>"#
    } else {
        r#"<a href="/login">Log in with Auth0</a>"#
    };
    Html(html.to_string())
}

// Redirect user to Auth0
async fn login(session: Session) -> impl IntoResponse {
    let client = OIDC_CLIENT.get().unwrap();
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
    let (auth_url, csrf_token, nonce) = client
        .authorize_url(
            AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        .set_pkce_challenge(pkce_challenge)
        .add_scope(Scope::new("openid".into()))
        .url();

    if let Err(err) = session.remove::<String>("id_token").await {
        eprintln!("Failed to clear id_token from session: {err}");
    }
    if let Err(err) = session
        .insert("pkce_verifier", pkce_verifier.secret().to_string())
        .await
    {
        eprintln!("Failed to store PKCE verifier in session: {err}");
    }
    if let Err(err) = session
        .insert("csrf_state", csrf_token.secret().to_string())
        .await
    {
        eprintln!("Failed to store CSRF state in session: {err}");
    }
    if let Err(err) = session.insert("nonce", nonce.secret().to_string()).await {
        eprintln!("Failed to store nonce in session: {err}");
    }

    Redirect::to(auth_url.as_ref())
}

// Handle Auth0 callback and store ID token
async fn callback(session: Session, Query(params): Query<CallbackParams>) -> impl IntoResponse {
    let client = OIDC_CLIENT.get().unwrap();

    let stored_csrf = match session.remove::<String>("csrf_state").await {
        Ok(Some(value)) => value,
        Ok(None) => return Html("CSRF check failed".to_string()).into_response(),
        Err(err) => {
            eprintln!("Failed to load csrf_state from session: {err}");
            return Html("Session error".to_string()).into_response();
        }
    };
    if params.state != stored_csrf {
        return Html("CSRF check failed".to_string()).into_response();
    }

    let pkce = match session.remove::<String>("pkce_verifier").await {
        Ok(Some(value)) => value,
        Ok(None) => return Html("Missing PKCE verifier".to_string()).into_response(),
        Err(err) => {
            eprintln!("Failed to load pkce_verifier from session: {err}");
            return Html("Session error".to_string()).into_response();
        }
    };
    let nonce = match session.remove::<String>("nonce").await {
        Ok(Some(value)) => value,
        Ok(None) => return Html("Missing nonce".to_string()).into_response(),
        Err(err) => {
            eprintln!("Failed to load nonce from session: {err}");
            return Html("Session error".to_string()).into_response();
        }
    };
    let pkce_verifier = PkceCodeVerifier::new(pkce);
    let token = client
        .exchange_code(AuthorizationCode::new(params.code))
        .set_pkce_verifier(pkce_verifier)
        .request_async(async_http_client)
        .await
        .unwrap();

    let id_token = token.id_token().unwrap();
    let _claims = id_token
        .claims(&client.id_token_verifier(), &Nonce::new(nonce.clone()))
        .unwrap();
    if let Err(err) = session.insert("id_token", id_token.to_string()).await {
        eprintln!("Failed to store id_token in session: {err}");
    }

    Redirect::to("/issue-vc").into_response()
}

// Issue and return a signed VC as JSON
async fn issue_vc(session: Session) -> impl IntoResponse {
    let id_token = match session.get::<String>("id_token").await {
        Ok(Some(token)) => token,
        Ok(None) => return Html("Unauthorized: please log in first".to_string()).into_response(),
        Err(err) => {
            eprintln!("Failed to read id_token from session: {err}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Session error".to_string(),
            )
                .into_response();
        }
    };

    match issue_signed_vc(id_token).await {
        Ok(credential) => Json(credential).into_response(),
        Err(message) => {
            eprintln!("Failed to issue credential: {message}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to issue credential".to_string(),
            )
                .into_response()
        }
    }
}

async fn issue_vc_qr(session: Session) -> impl IntoResponse {
    let id_token = match session.get::<String>("id_token").await {
        Ok(Some(token)) => token,
        Ok(None) => return Html("Unauthorized: please log in first".to_string()).into_response(),
        Err(err) => {
            eprintln!("Failed to read id_token from session: {err}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Session error".to_string(),
            )
                .into_response();
        }
    };

    match issue_signed_vc(id_token).await {
        Ok(credential) => {
            let payload = match serde_json::to_string(&credential) {
                Ok(value) => value,
                Err(err) => {
                    eprintln!("Failed to serialize credential to string: {err}");
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Failed to prepare credential payload".to_string(),
                    )
                        .into_response();
                }
            };

            let qr_code = match QrCode::new(&payload) {
                Ok(code) => code,
                Err(err) => {
                    eprintln!("Failed to encode credential into QR: {err}");
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Credential payload is too large to encode as QR".to_string(),
                    )
                        .into_response();
                }
            };

            let svg_image = qr_code
                .render::<svg::Color>()
                .min_dimensions(320, 320)
                .max_dimensions(320, 320)
                .dark_color(svg::Color("#0f172a"))
                .light_color(svg::Color("#ffffff"))
                .build();

            let data_uri = format!(
                "data:image/svg+xml;base64,{}",
                BASE64_STANDARD.encode(svg_image.as_bytes())
            );

            let pretty_json = match serde_json::to_string_pretty(&credential) {
                Ok(value) => value,
                Err(err) => {
                    eprintln!("Failed to produce pretty credential JSON: {err}");
                    String::new()
                }
            };

            let html = format!(
                r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Auth0 VC QR Code</title>
  <style>
    body {{ font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; margin: 2rem; color: #0f172a; background-color: #f8fafc; }}
    h1, h2 {{ color: #0f172a; }}
    .card {{ background: #ffffff; padding: 1.5rem; border-radius: 0.75rem; box-shadow: 0 10px 30px rgba(15, 23, 42, 0.1); max-width: 640px; margin: 0 auto; }}
    .qr {{ display: flex; justify-content: center; margin: 2rem 0; }}
    img {{ border: 12px solid #ffffff; border-radius: 1rem; box-shadow: 0 8px 24px rgba(15, 23, 42, 0.12); }}
    textarea {{ width: 100%; min-height: 160px; margin-top: 0.75rem; border-radius: 0.5rem; border: 1px solid #cbd5f5; padding: 0.75rem; font-family: "SFMono-Regular", Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace; font-size: 0.85rem; background: #f1f5f9; color: #0f172a; }}
    pre {{ background: #0f172a; color: #e2e8f0; padding: 1rem; border-radius: 0.5rem; overflow-x: auto; font-size: 0.85rem; }}
    .hint {{ color: #475569; font-size: 0.95rem; }}
  </style>
</head>
<body>
  <div class="card">
    <h1>Verifiable Credential QR Code</h1>
    <p class="hint">Scan this QR code with a compatible digital wallet to add the issued credential. The QR encodes the signed credential in compact JSON form.</p>
    <div class="qr">
      <img src="{data_uri}" alt="Verifiable Credential QR" width="320" height="320" />
    </div>
    <h2>Raw QR payload</h2>
    <p class="hint">Copy this value if you need to transfer the credential without scanning the QR code.</p>
    <textarea readonly>{raw_payload}</textarea>
    <h2>Pretty JSON</h2>
    <pre>{credential_json}</pre>
  </div>
</body>
</html>"#,
                data_uri = data_uri,
                raw_payload = html_escape(&payload),
                credential_json = html_escape(&pretty_json),
            );

            Html(html).into_response()
        }
        Err(message) => {
            eprintln!("Failed to issue credential: {message}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to issue credential".to_string(),
            )
                .into_response()
        }
    }
}

async fn issue_signed_vc(id_token: String) -> Result<serde_json::Value, String> {
    let config = ISSUER_CONFIG
        .get()
        .ok_or_else(|| "Issuer configuration is not initialized".to_string())?;

    let credential_json = json!({
        "@context": [
            "https://www.w3.org/2018/credentials/v1",
            {
                "Auth0IdTokenCredential": "https://schemas.auth0.com/credentials/Auth0IdTokenCredential",
                "idToken": "https://schemas.auth0.com/claims/idToken"
            }
        ],
        "type": ["VerifiableCredential", "Auth0IdTokenCredential"],
        "issuer": config.issuer,
        "issuanceDate": DateTime::now(),
        "id": format!("urn:uuid:{}", Uuid::new_v4()),
        "credentialSubject": {
            "id": format!("urn:uuid:{}", Uuid::new_v4()),
            "idToken": id_token,
        }
    });

    let credential: JsonCredential = serde_json::from_value(credential_json)
        .map_err(|err| format!("Failed to construct credential payload: {err}"))?;

    let vm_iri = IriBuf::new(config.verification_method.clone())
        .map_err(|err| format!("Invalid verification method URI: {err}"))?;

    let mut proof_options = ProofOptions::from_method(ReferenceOrOwned::Reference(vm_iri));
    proof_options.proof_purpose = ProofPurpose::Assertion;

    let resolver = VerificationMethodDIDResolver::<_, AnyMethod>::new(AnyDidMethod::default());
    let jwk = (*config.jwk).clone();
    let signer = SingleSecretSigner::new(jwk.clone()).into_local();

    let suite = AnySuite::pick(&jwk, proof_options.verification_method.as_ref())
        .ok_or_else(|| "No compatible signature suite for the configured key".to_string())?;

    let signed_vc = suite
        .sign(credential, &resolver, &signer, proof_options)
        .await
        .map_err(|err| format!("Failed to sign credential: {err}"))?;

    let verification = signed_vc
        .verify(VerificationParameters::from_resolver(
            VerificationMethodDIDResolver::<_, AnyMethod>::new(AnyDidMethod::default()),
        ))
        .await
        .map_err(|err| format!("Failed to verify issued credential: {err}"))?;

    if let Err(err) = verification {
        return Err(format!("Credential verification failed: {err}"));
    }

    serde_json::to_value(&signed_vc).map_err(|err| format!("Failed to serialize credential: {err}"))
}

fn load_issuer_config() -> IssuerConfig {
    let mut jwk = match env::var("ISSUER_JWK") {
        Ok(jwk_raw) => {
            let parsed: JWK =
                serde_json::from_str(&jwk_raw).expect("ISSUER_JWK must be valid JWK JSON");
            parsed
        }
        Err(env::VarError::NotPresent) => {
            let generated =
                JWK::generate_ed25519().expect("Failed to generate fallback Ed25519 key");
            eprintln!("ISSUER_JWK not set; generated an ephemeral Ed25519 key for this process");
            generated
        }
        Err(env::VarError::NotUnicode(_)) => {
            panic!("ISSUER_JWK contained invalid UTF-8 data")
        }
    };

    if jwk.algorithm.is_none() {
        jwk.algorithm = Some(Algorithm::EdDSA);
    }

    let public_jwk = jwk.to_public();

    let default_issuer = DIDKey::generate(&public_jwk)
        .expect("Unable to derive did:key identifier from ISSUER_JWK")
        .to_string();

    let issuer = env::var("ISSUER_DID").unwrap_or(default_issuer);

    let default_verification_method = DIDKey::generate_url(&public_jwk)
        .expect("Unable to derive verification method from ISSUER_JWK")
        .to_string();

    let verification_method =
        env::var("ISSUER_VERIFICATION_METHOD").unwrap_or(default_verification_method);

    if jwk.key_id.is_none() {
        jwk.key_id = Some(verification_method.clone());
    }

    IssuerConfig {
        jwk: Arc::new(jwk),
        issuer,
        verification_method,
    }
}

fn derive_session_secret() -> Vec<u8> {
    let raw = env::var("SESSION_SECRET").expect("SESSION_SECRET environment variable must be set");

    if let Ok(decoded) = BASE64_STANDARD.decode(raw.as_bytes()) {
        if decoded.len() >= 64 {
            return decoded;
        }
    }

    let raw_bytes = raw.into_bytes();
    if raw_bytes.len() >= 64 {
        return raw_bytes;
    }

    eprintln!(
        "SESSION_SECRET is shorter than 64 bytes; deriving a 64-byte key using SHA-512. Consider providing a longer or base64-encoded secret for production."
    );

    let mut hasher = Sha512::new();
    hasher.update(&raw_bytes);
    hasher.finalize().to_vec()
}

fn html_escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}
