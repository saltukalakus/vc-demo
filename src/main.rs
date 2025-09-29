use axum::{
    extract::Query,
    response::{Html, IntoResponse, Redirect},
    routing::get,
    Json, Router,
};
use axum_sessions::{
    async_session::MemoryStore,
    extractors::WritableSession,
    SessionLayer,
};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use chrono::Utc;
use dotenv::dotenv;
use openidconnect::{
    core::{CoreClient, CoreProviderMetadata, CoreResponseType},
    reqwest::async_http_client,
    AuthenticationFlow, AuthorizationCode, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce,
    PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope, TokenResponse,
};
use serde::Deserialize;
use serde_json::json;
use std::env;
use tokio::sync::OnceCell;
use uuid::Uuid;
use sha2::{Digest, Sha512};

// Shared OpenID client in app state
static OIDC_CLIENT: OnceCell<CoreClient> = OnceCell::const_new();

#[derive(Deserialize)]
struct CallbackParams {
    code: String,
    state: String,
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
        Some(ClientSecret::new(
            env::var("AUTH0_CLIENT_SECRET").unwrap(),
        )),
    )
    .set_redirect_uri(RedirectUrl::new(env::var("AUTH0_REDIRECT_URL").unwrap()).unwrap());

    OIDC_CLIENT.set(client).unwrap();

    // Session middleware
    let secret = derive_session_secret();
    let store = MemoryStore::new();
    let session_layer = SessionLayer::new(store, secret.as_slice()).with_secure(false);

    // Build the router
    let app = Router::new()
        .route("/", get(index))
        .route("/login", get(login))
        .route("/callback", get(callback))
        .route("/issue-vc", get(issue_vc))
        .layer(session_layer);

    println!("Listening on http://localhost:8080");
    axum::Server::bind(&"0.0.0.0:8080".parse().unwrap())
        .serve(app.into_make_service())
        .await
        .unwrap();
}

// Public landing page
async fn index(session: WritableSession) -> impl IntoResponse {
    let logged_in = session.get::<String>("id_token").is_some();
    let html = if logged_in {
        r#"<h2>Authenticated</h2>
           <a href="/issue-vc">Issue VC</a>"#
    } else {
        r#"<a href="/login">Log in with Auth0</a>"#
    };
    Html(html.to_string())
}

// Redirect user to Auth0
async fn login(mut session: WritableSession) -> impl IntoResponse {
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

    session.remove("id_token");
    session
        .insert("pkce_verifier", pkce_verifier.secret().to_string())
        .unwrap();
    session
        .insert("csrf_state", csrf_token.secret().to_string())
        .unwrap();
    session
        .insert("nonce", nonce.secret().to_string())
        .unwrap();

    Redirect::to(auth_url.as_ref())
}

// Handle Auth0 callback and store ID token
async fn callback(
    mut session: WritableSession,
    Query(params): Query<CallbackParams>,
) -> impl IntoResponse {
    let client = OIDC_CLIENT.get().unwrap();

    let stored_csrf = match session.get::<String>("csrf_state") {
        Some(value) => value,
        None => return Html("CSRF check failed".to_string()).into_response(),
    };
    if params.state != stored_csrf {
        return Html("CSRF check failed".to_string()).into_response();
    }

    session.remove("csrf_state");

    let pkce = match session.get::<String>("pkce_verifier") {
        Some(value) => value,
        None => return Html("Missing PKCE verifier".to_string()).into_response(),
    };
    session.remove("pkce_verifier");
    let nonce = match session.get::<String>("nonce") {
        Some(value) => value,
        None => return Html("Missing nonce".to_string()).into_response(),
    };
    session.remove("nonce");
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
    session
        .insert("id_token", id_token.to_string())
        .unwrap();

    Redirect::to("/issue-vc").into_response()
}

// Issue and return a signed VC as JSON
async fn issue_vc(session: WritableSession) -> impl IntoResponse {
    if let Some(id_token) = session.get::<String>("id_token") {
        let credential = json!({
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "id": format!("urn:uuid:{}", Uuid::new_v4()),
            "type": ["VerifiableCredential"],
            "issuer": {
                "id": format!("did:example:issuer:{}", Uuid::new_v4()),
                "name": "Axum VC Demo"
            },
            "issuanceDate": Utc::now().to_rfc3339(),
            "credentialSubject": {
                "id": format!("did:example:subject:{}", Uuid::new_v4()),
                "id_token": id_token,
            }
        });

        return Json(credential).into_response();
    }

    Html("Unauthorized: please log in first".to_string()).into_response()
}

fn derive_session_secret() -> Vec<u8> {
    let raw = env::var("SESSION_SECRET")
        .expect("SESSION_SECRET environment variable must be set");

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
