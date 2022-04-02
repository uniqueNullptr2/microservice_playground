use core::{generate_access_token, rand, generate_reftesh_token, ErrorResponse};
use std::{sync::Arc, collections::HashMap};

use actix_web::{HttpServer, App, middleware, HttpResponse, web::{self, Data}, post, Responder, http::StatusCode};
use serde::{Serialize, Deserialize};
use tokio::sync::RwLock;

#[derive(Clone)]
struct UserManager {
    sessions: Arc<RwLock<HashMap<String,String>>>,
    _user_essions: Arc<RwLock<HashMap<String,String>>>,
    users: Arc<RwLock<HashMap<String,String>>>,
    secret: String
}

impl UserManager {
    fn set_secret(&mut self, secret: &str) {
        self.secret = secret.to_owned();
    }

    async fn add_user(&mut self, name: &str, pass: &str) -> bool {
        if self.users.read().await.contains_key(name) {
            false
        } else {
            self.users.write().await.insert(name.to_owned(), pass.to_owned());
            true
        }
    }

    async fn login(&self, name: &str, pass: &str) -> Option<TokenResponse> {
        if let Some(_) = self.users.read().await.get(name).filter(|p| p == &pass) {
            let mut rng = rand::thread_rng();
            let refresh = generate_reftesh_token(&mut rng);
            self.sessions.write().await.insert(refresh.to_owned(), name.to_owned());
            let access = generate_access_token(&self.secret, name);
            Some(TokenResponse{success:true, refresh_token: Some(refresh), access_token: Some(access)})
        } else {
            None
        }
    }

    async fn refresh_token(&self, refresh_token: &str) -> Option<TokenResponse> {
        if let Some(name) = self.sessions.read().await.get(refresh_token) {
            let access = generate_access_token(&self.secret, name);
            Some(TokenResponse{success:true, refresh_token: Some(refresh_token.to_owned()), access_token: Some(access)})
        } else {
            None
        }
    }
}
impl Default for UserManager {
    fn default() -> Self {
        UserManager{
            sessions: Arc::new(RwLock::new(HashMap::<String,String>::new())),
            users: Arc::new(RwLock::new(HashMap::<String,String>::new())),
            _user_essions: Arc::new(RwLock::new(HashMap::<String,String>::new())),
            secret: "".to_owned()
        }
    }
}


#[derive(Serialize,Deserialize,Debug,Clone)]
struct TokenResponse {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    access_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    refresh_token: Option<String>
}
impl Default for TokenResponse {
    fn default() -> Self {
        Self{success:false, access_token: None, refresh_token: None}
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()>  {
    let secret = "supersecret_tokenSecretYoIcannotBeliefIt".to_owned();
    let mut data = UserManager::default();
    data.add_user("Phil", "+Test12345").await;
    data.set_secret(&secret);

    HttpServer::new(move || {
        App::new()
            .wrap(middleware::Compress::default())
            .service(web::resource("/health").to(health))
            .app_data(Data::new(data.clone()))
            .app_data(secret.clone())
            .service(login)
            .service(refresh_token_route)

    })
    .bind(("0.0.0.0", 8080))?
    .run()
    .await
}

async fn health() -> HttpResponse {
    HttpResponse::Ok().finish()
}

#[post("/login")]
async fn login(login: web::Json<Login>, data: Data<UserManager>) -> Result<impl Responder, ErrorResponse> {
    if let Some(response) =  data.login(login.username.as_str(), login.password.as_str()).await {
        Ok(web::Json(response))
    } else {
        Err(ErrorResponse::from_struct(TokenResponse::default()).with_code(StatusCode::BAD_REQUEST))
    }
}

#[post("/refresh")]
async fn refresh_token_route(refresh: web::Json<RefreshRequest>, data: Data<UserManager>) -> impl Responder {
    web::Json(data.refresh_token(refresh.token.as_str()).await.unwrap_or_default())
}

#[derive(Serialize, Deserialize, Debug,Clone)]
struct RefreshRequest {
    token: String
}

#[derive(Serialize, Deserialize,Debug,Clone)]
struct Login {
    username: String,
    password: String,
}