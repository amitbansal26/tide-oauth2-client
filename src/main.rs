mod config;
use crate::config::Config;

use actix_session::{CookieSession, Session};
use actix_web::http::header;
use actix_web::middleware::Logger;
use actix_web::web;
use actix_web::{App, HttpResponse, HttpServer};
use oauth2::basic::BasicClient;
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, PkceCodeChallenge, RedirectUrl,
    Scope, TokenUrl,
};
use serde::{Deserialize, Serialize};
use tracing::{info, instrument};
use tracing_futures::Instrument;
use tracing_subscriber::EnvFilter;

#[derive(Debug)]
struct AppState {
    oauth: BasicClient,
}

fn index(session: Session) -> HttpResponse {
    let link = if let Some(_login) = session.get::<bool>("login").unwrap() {
        "logout"
    } else {
        "login"
    };

    let html = format!(
        r#"<html>
        <head><title>OAuth2 Test</title></head>
        <body>
            <a href="/{}">{}</a>
        </body>
    </html>"#,
        link, link
    );

    HttpResponse::Ok().body(html)
}

#[actix_rt::main]
async fn main() {
    let config = Config::from_env().expect("Server configuration");
    info!("Loading Configuration");
    HttpServer::new(|| {
        let keycloak_client_id = ClientId::new(String::from("rust-microservice"));
        let google_client_secret =
            ClientSecret::new(String::from("d3b0fbf3-7d0d-4d99-bd1c-697febc6147d"));
        let auth_url = AuthUrl::new(
            "http://localhost:8080/auth/realms/dev/protocol/openid-connect/auth".to_string(),
        )
        .expect("Invalid authorization endpoint URL");
        let token_url = TokenUrl::new(
            "http://localhost:8080/auth/realms/dev/protocol/openid-connect/token".to_string(),
        )
        .expect("Invalid token endpoint URL");

        // Set up the config for the Google OAuth2 process.
        let client = BasicClient::new(
            keycloak_client_id,
            Some(google_client_secret),
            auth_url,
            Some(token_url),
        );

        App::new()
            .data(AppState { oauth: client })
            .wrap(CookieSession::signed(&[0; 32]).secure(false))
            .wrap(Logger::default())
            .route("/", web::get().to(index))
            .route("/login", web::get().to(login))
            .route("/logout", web::get().to(logout))
            .route("/auth", web::get().to(auth))
    })
    .bind("127.0.0.1:8085")
    .expect("Can not bind to port 8085")
    .run()
    .await
    .unwrap();
}

fn login(data: web::Data<AppState>) -> HttpResponse {
    let (pkce_code_challange, _pkce_code_verifier) = PkceCodeChallenge::new_random_sha256();

    let (authorize_url, _csrf_state) = &data
        .oauth
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new("rustscope".to_string()))
        .set_pkce_challenge(pkce_code_challange)
        .url();
    info!("Auth url {}", authorize_url);
    HttpResponse::Found()
        .header(header::LOCATION, authorize_url.to_string())
        .finish()
}
fn logout(session: Session) -> HttpResponse {
    session.remove("login");
    HttpResponse::Found()
        .header(header::LOCATION, "/".to_string())
        .finish()
}
#[derive(Deserialize, Serialize, Debug)]
pub struct AuthRequest {
    code: String,
    state: String,
    scope: String,
}

fn auth(
    session: Session,
    data: web::Data<AppState>,
    params: web::Query<AuthRequest>,
) -> HttpResponse {
    let code = AuthorizationCode::new(params.code.clone());
    let state = CsrfToken::new(params.state.clone());
    let scope = params.scope.clone();

    // Exchange the code with a token.
    let token = &data.oauth.exchange_code(code);
    session.set("login", true).unwrap();

    let html = format!(
        r#"<html>
        <head><title>OAuth2 Test</title></head>
        <body>
            Keycloak returned the following state:
            <pre>{}</pre>
            Keycloak returned the following token:
            <pre>{:?}</pre>
        </body>
    </html>"#,
        state.secret(),
        token,
    );

    HttpResponse::Ok().body(html)
}
