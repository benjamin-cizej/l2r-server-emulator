use crate::network::listener::Acceptable;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use tokio::net::{TcpListener, TcpStream};

impl Acceptable for TcpListener {
    type Output = TcpStream;

    fn accept_connection<'a>(
        &'a self,
    ) -> Pin<
        Box<dyn std::future::Future<Output = io::Result<(Self::Output, SocketAddr)>> + Send + 'a>,
    > {
        Box::pin(async move {
            let (stream, addr) = self.accept().await?;
            stream.set_nodelay(true)?;

            Ok((stream, addr))
        })
    }
}
