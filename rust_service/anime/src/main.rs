use core::{User};
use std::env;
use actix_web::{HttpServer, App, middleware, HttpResponse, web::{self,}, Responder, get};

#[actix_web::main]
async fn main() -> std::io::Result<()>  {
    let secret = env::var("ACTIX_JWT_SECRET").unwrap_or("jy<q|ezip5,Q%^xBZz{I|M*zdW}xX>|;:LMc<C{%`(b8wCI/#$h[#ws+/XLvnyq".to_owned());
    let port = env::var("ACTIX_PORT").ok().map(|s| s.parse().ok()).flatten().unwrap_or(8080);

    HttpServer::new(move || {
        App::new()
            .wrap(middleware::Compress::default())
            .service(web::resource("/health").to(health))
            .app_data(secret.clone())
            .service(authed_hello)

    })
    .bind(("0.0.0.0", port))?
    .run()
    .await
}

#[get("/authedhello")]
async fn authed_hello(user: User) -> impl Responder {
    format!("Hello there {}", user.name)
}

async fn health() -> HttpResponse {
    HttpResponse::Ok().finish()
}