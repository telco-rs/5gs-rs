use axum::Router;
use axum::routing::get;
use std::net::SocketAddr;

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/health", get(health_check))
        .route("/api/users", get(get_users).post(create_user))
        .route("/api/users/:id", get(get_user_by_id));

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
