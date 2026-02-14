use axum::Router;
use std::net::SocketAddr;

#[tokio::main]
async fn main() {
    let app = Router::new();

    let addr = SocketAddr::from(([127, 0, 0, 1], 29510));

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}