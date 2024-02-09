use crate::network::socket::Socket;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use tokio::net::{TcpSocket, TcpStream};

impl Socket for TcpSocket {
    type Output = TcpStream;

    fn connect<'a>(
        &'a mut self,
        addr: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = std::io::Result<Self::Output>> + Send + 'a>> {
        Box::pin(async move {
            let socket = TcpSocket::new_v4()?;
            socket.connect(addr).await
        })
    }
}
