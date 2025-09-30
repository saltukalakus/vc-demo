use axum::{
    extract::Query,
    response::{Html, IntoResponse, Redirect},
    routing::get,
    Json, Router,
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
use tokio::{net::TcpListener, sync::OnceCell};
use uuid::Uuid;
use sha2::{Digest, Sha512};
use tower_sessions::{cookie::Key, MemoryStore, Session, SessionManagerLayer};

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
    if let Err(err) = session
        .insert("nonce", nonce.secret().to_string())
        .await
    {
        eprintln!("Failed to store nonce in session: {err}");
    }

    Redirect::to(auth_url.as_ref())
}

// Handle Auth0 callback and store ID token
async fn callback(
    session: Session,
    Query(params): Query<CallbackParams>,
) -> impl IntoResponse {
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
    if let Ok(Some(id_token)) = session.get::<String>("id_token").await {
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
