use crate::network::channel::channel_connection::ChannelConnector;
use crate::network::channel::channel_stream::ChannelStream;
use crate::network::listener::Acceptable;
use std::future::Future;
use std::io;
use std::io::ErrorKind::ConnectionRefused;
use std::net::SocketAddr;
use std::pin::Pin;
use tokio::sync::mpsc::{channel, Receiver, Sender};

pub struct ChannelListener {
    tx: ChannelConnector,
    rx: Receiver<(Sender<Vec<u8>>, Sender<Sender<Vec<u8>>>)>,
}

impl ChannelListener {
    pub fn new() -> Self {
        let (tx, rx) = channel(10);

        Self { tx, rx }
    }

    pub fn get_connector(&self) -> ChannelConnector {
        self.tx.clone()
    }
}

impl Acceptable for ChannelListener {
    type Output = ChannelStream;

    fn accept_connection<'a>(
        &'a mut self,
    ) -> Pin<Box<dyn Future<Output = io::Result<(Self::Output, SocketAddr)>> + Send + 'a>> {
        Box::pin(async move {
            let (byte_writer, sender) = match self.rx.recv().await {
                Some((first, second)) => (first, second),
                None => return Err(io::Error::from(ConnectionRefused)),
            };

            let (tx, byte_reader) = channel(10);
            let stream = ChannelStream::build(byte_writer, byte_reader);

            if let Err(_) = sender.send(tx).await {
                return Err(io::Error::from(ConnectionRefused));
            }

            Ok((stream, SocketAddr::new("127.0.0.1".parse().unwrap(), 0)))
        })
    }
}
