use std::{fmt::Display, future::{Ready, self}, ops::Not};

use actix_web::{http::{StatusCode, header::HeaderValue}, ResponseError, HttpResponse, FromRequest, Error, error::{ErrorUnauthorized, ErrorInternalServerError}};
use chrono::Utc;
use jsonwebtoken::{EncodingKey, Header, encode, DecodingKey, Validation, decode};
use rand::Rng;
use anyhow::Result;
use serde::{Serialize, Deserialize};

pub use rand;

#[derive(Deserialize, Serialize, Debug)]
pub struct TokenClaims {
    username: String,
    user_id: u32,
    exp: usize
}

pub fn generate_reftesh_token<R: Rng + ?Sized>(r: &mut R) -> String {
    let s = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+*#-_!$%&".as_bytes();
    String::from_utf8((0..64).into_iter().map(|_| {
        let i = r.gen_range(0..s.len());
        s[i]
    }).collect()).unwrap()
}

pub fn generate_access_token(secret: &str, username: &str) -> String {
    let exp = Utc::now().checked_add_signed(chrono::Duration::minutes(15)).unwrap().timestamp_millis() as usize;
    let claims = TokenClaims{username: username.to_owned(), user_id: 1337, exp};
    let token_str = encode(&Header::default(), &claims, &EncodingKey::from_secret(secret.as_bytes())).unwrap();
    token_str
}

pub fn validate_token(secret: &str, token: &str) -> Result<TokenClaims>{
    let claims = decode::<TokenClaims>(token, &DecodingKey::from_secret(secret.as_bytes()), &Validation::default())?;
    Ok(claims.claims)
}

#[derive(Debug)]
pub struct ErrorResponse {
    json: String,
    code: StatusCode
}

impl Display for ErrorResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.json)
    }
}

impl ErrorResponse {
    pub fn from_struct<S: Serialize>(input: S) -> Self {
        //TODO safer??
        let json = serde_json::to_string(&input).unwrap();
        Self{json, code: StatusCode::OK}
    }
    pub fn with_code(mut self, code: StatusCode) -> Self {
        self.code = code;
        self
    }
}

impl ResponseError for ErrorResponse {
    fn status_code(&self) -> StatusCode {
        self.code
    }

    fn error_response(&self) -> HttpResponse<actix_web::body::BoxBody> {
        let mut res = HttpResponse::new(self.status_code());
        res.headers_mut().insert(actix_web::http::header::CONTENT_TYPE, HeaderValue::from_str("application/json").unwrap());

        res.set_body(actix_web::body::BoxBody::new(self.json.to_owned()))
    }
}

pub struct User {
    pub name: String,
    pub id: u32
}

impl User {
    pub fn new(name: &str, id: u32) -> Self {
        Self{name: name.to_owned(), id}
    }
}

impl FromRequest for User {
    type Error = Error;

    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &actix_web::HttpRequest, _payload: &mut actix_web::dev::Payload) -> Self::Future {
        let r = req.headers().get("Authorization")
            .ok_or(ErrorUnauthorized("Authorization header missing"))
            .and_then(|h| {
                let token = h.to_str().map_err(|e| ErrorUnauthorized(e.to_string()))?;
                if token.starts_with("Bearer ").not() {
                    Err(ErrorUnauthorized("Value doesnt start with Bearer"))?;
                }
                let jwt = &token[7..];
                let secret = req.app_data::<String>().ok_or(ErrorInternalServerError("Misconfigured"))?;
                validate_token(secret, jwt)
                    .map(|tc| User{name: tc.username, id: tc.user_id}).map_err(|e| ErrorUnauthorized(e.to_string()))
            });
        future::ready(r)
    }
}