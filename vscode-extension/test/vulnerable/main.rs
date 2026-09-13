// Ch3ck3r SAST Vulnerable Test — Rust
// Deliberate security flaws for detection testing

use actix_web::{web, App, HttpServer, HttpResponse};
use serde::Deserialize;
use sqlx::PgPool;
use std::process::Command;
use std::fs;

// 🔴 CWE-798 Hardcoded secrets
const JWT_SECRET: &str = "my_secret_key";
const API_KEY: &str = "sk-live-abcdef123456";

#[derive(Deserialize)]
struct UserQuery {
    id: String,
}

#[derive(Deserialize)]
struct ProxyBody {
    url: String,
}

#[derive(Deserialize)]
struct ExecQuery {
    cmd: String,
}

// 🔴 CWE-285 Missing auth
#[get("/api/users/{id}")]
async fn get_user(pool: web::Data<PgPool>, path: web::Path<String>) -> HttpResponse {
    let user_id = path.into_inner();

    // 🔴 CWE-89 SQL Injection via format!
    let query = format!("SELECT * FROM users WHERE id = {}", user_id);
    let result = sqlx::query(&query).fetch_all(pool.get_ref()).await;

    // 🔴 CWE-200 Expose sensitive data
    HttpResponse::Ok().json(result)
}

// 🔴 CWE-918 SSRF — user-controlled URL
#[post("/api/proxy")]
async fn proxy(body: web::Json<ProxyBody>) -> HttpResponse {
    let url = &body.url;
    // No validation of URL
    let response = reqwest::get(url).await.unwrap();
    let text = response.text().await.unwrap();
    HttpResponse::Ok().body(text)
}

// 🔴 CWE-78 Command injection
#[get("/api/exec")]
async fn exec_cmd(query: web::Query<ExecQuery>) -> HttpResponse {
    let cmd = &query.cmd;
    // 🔴 shell=True via sh -c
    let output = Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .output()
        .unwrap();
    HttpResponse::Ok().body(output.stdout)
}

// 🔴 CWE-22 Path traversal
#[get("/api/read")]
async fn read_file(query: web::Query<PathQuery>) -> HttpResponse {
    let path = &query.path;
    let content = fs::read_to_string(format!("/data/{}", path)).unwrap();
    HttpResponse::Ok().body(content)
}

// 🔴 CWE-639 IDOR — no ownership
#[delete("/api/users/{id}")]
async fn delete_user(pool: web::Data<PgPool>, path: web::Path<String>) -> HttpResponse {
    let query = format!("DELETE FROM users WHERE id = {}", path.into_inner());
    sqlx::query(&query).execute(pool.get_ref()).await.unwrap();
    HttpResponse::Ok().json(serde_json::json!({"deleted": true}))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new()
            .service(get_user)
            .service(proxy)
            .service(exec_cmd)
            .service(read_file)
            .service(delete_user)
    })
    .bind("0.0.0.0:8080")?
    .run()
    .await
}
