use crate::network::stream::Streamable;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;

pub trait Socket {
    type Output: Streamable + Send + 'static;

    fn connect<'a>(
        &'a mut self,
        addr: SocketAddr,
    ) -> Pin<Box<dyn std::future::Future<Output = io::Result<Self::Output>> + Send + 'a>>;
}
