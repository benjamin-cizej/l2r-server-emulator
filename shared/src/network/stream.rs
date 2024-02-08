use std::pin::Pin;
use tokio::io;

pub trait Streamable: Send {
    fn send_bytes<'a>(
        &'a mut self,
        buf: &'a [u8],
    ) -> Pin<Box<dyn std::future::Future<Output = io::Result<()>> + Send + 'a>>;

    fn receive_bytes<'a>(
        &'a mut self,
        buf: &'a mut [u8],
    ) -> Pin<Box<dyn std::future::Future<Output = io::Result<usize>> + Send + 'a>>;
}
