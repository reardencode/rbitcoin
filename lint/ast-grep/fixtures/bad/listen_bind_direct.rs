async fn serve(addr: std::net::SocketAddr) {
    let _l = tokio::net::TcpListener::bind(addr).await;
}

async fn serve_short(addr: std::net::SocketAddr) {
    let _l = TcpListener::bind(addr).await;
}

fn serve_std(addr: std::net::SocketAddr) {
    let _l = std::net::TcpListener::bind(addr);
}
