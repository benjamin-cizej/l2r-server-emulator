use crate::network::channel::channel_connection::{connect, ChannelConnector};
use crate::network::channel::channel_stream::ChannelStream;
use crate::network::socket::Socket;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;

pub struct ChannelSocket<'a> {
    connector: &'a mut ChannelConnector,
}

impl<'a> ChannelSocket<'a> {
    pub fn new(connector: &'a mut ChannelConnector) -> Self {
        ChannelSocket { connector }
    }
}

impl<'a> Socket for ChannelSocket<'a> {
    type Output = ChannelStream;

    fn connect<'b>(
        &'b mut self,
        _addr: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = std::io::Result<Self::Output>> + Send + 'b>> {
        Box::pin(async move { connect(&mut self.connector).await })
    }
}
