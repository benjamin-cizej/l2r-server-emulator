use crate::network::stream::Streamable;
use std::pin::Pin;
use tokio::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

impl Streamable for TcpStream {
    fn send_bytes<'a>(
        &'a mut self,
        buf: &'a [u8],
    ) -> Pin<Box<dyn std::future::Future<Output = io::Result<()>> + Send + 'a>> {
        Box::pin(async move {
            self.write_all(buf).await?;
            self.flush().await?;
            Ok(())
        })
    }

    fn receive_bytes<'a>(
        &'a mut self,
        buf: &'a mut [u8],
    ) -> Pin<Box<dyn std::future::Future<Output = io::Result<usize>> + Send + 'a>> {
        Box::pin(async move {
            let n = self.read(buf).await?;
            Ok(n)
        })
    }
}
