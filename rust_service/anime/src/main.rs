use core::{User};
use actix_web::{HttpServer, App, middleware, HttpResponse, web::{self,}, Responder, get};

#[actix_web::main]
async fn main() -> std::io::Result<()>  {
    let secret = "supersecret_tokenSecretYoIcannotBeliefIt".to_owned();

    HttpServer::new(move || {
        App::new()
            .wrap(middleware::Compress::default())
            .service(web::resource("/health").to(health))
            .app_data(secret.clone())
            .service(authed_hello)

    })
    .bind(("0.0.0.0", 8081))?
    .run()
    .await
}

#[get("/authedhello")]
async fn authed_hello(user: User) -> impl Responder {
    format!("Hello {}", user.name)
}

async fn health() -> HttpResponse {
    HttpResponse::Ok().finish()
}