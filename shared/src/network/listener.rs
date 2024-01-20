use crate::network::stream::Streamable;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;

pub trait Acceptable {
    type Output: Streamable + Send + 'static;

    fn accept_connection<'a>(
        &'a self,
    ) -> Pin<
        Box<dyn std::future::Future<Output = io::Result<(Self::Output, SocketAddr)>> + Send + 'a>,
    >;
}
