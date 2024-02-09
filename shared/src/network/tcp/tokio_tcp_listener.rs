use crate::network::listener::{Acceptable, AcceptableResult};
use tokio::net::{TcpListener, TcpStream};

impl Acceptable for TcpListener {
    type Output = TcpStream;

    fn accept_connection(&mut self) -> AcceptableResult<Self::Output> {
        Box::pin(async move {
            let (stream, addr) = self.accept().await?;
            stream.set_nodelay(true)?;

            Ok((stream, addr))
        })
    }
}
