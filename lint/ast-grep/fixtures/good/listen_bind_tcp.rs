fn serve(addr: std::net::SocketAddr) {
    let _l = rbitcoin_net::listen::bind_tcp(addr);
}

#[cfg(test)]
mod tests {
    async fn fake_peer() {
        let _l = tokio::net::TcpListener::bind("127.0.0.1:0").await;
    }
}
