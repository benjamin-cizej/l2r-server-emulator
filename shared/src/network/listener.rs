use crate::network::stream::Streamable;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;

pub type AcceptableResult<'a, T> =
    Pin<Box<dyn std::future::Future<Output = io::Result<(T, SocketAddr)>> + Send + 'a>>;
pub trait Acceptable {
    type Output: Streamable + Send + 'static;

    fn accept_connection(&mut self) -> AcceptableResult<Self::Output>;
}
