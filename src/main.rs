use actix_session::{CookieSession, Session};
use actix_web::{App, HttpResponse, HttpServer};
use oauth2::basic::BasicClient;
use oauth2::{CsrfToken, PkceCodeChallenge, Scope};

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
    HttpServer::new(|| App::new().route("/", actix_web::web::get().to(index)))
        .bind("127.0.0.1:5000")
        .expect("Can not bind to port 5000")
        .run()
        .await
        .unwrap();
}
