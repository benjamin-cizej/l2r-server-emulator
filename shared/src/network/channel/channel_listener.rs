use crate::network::channel::channel_connection::ChannelConnector;
use crate::network::channel::channel_stream::ChannelStream;
use crate::network::listener::{Acceptable, AcceptableResult};
use std::io;
use std::io::ErrorKind::ConnectionRefused;
use std::net::SocketAddr;
use tokio::sync::mpsc::{channel, Receiver, Sender};

type ChannelReceiver = Receiver<(Sender<Vec<u8>>, Sender<Sender<Vec<u8>>>)>;

pub struct ChannelListener {
    tx: ChannelConnector,
    rx: ChannelReceiver,
}

impl ChannelListener {
    pub fn get_connector(&self) -> ChannelConnector {
        self.tx.clone()
    }
}

impl Default for ChannelListener {
    fn default() -> Self {
        let (tx, rx) = channel(10);

        Self { tx, rx }
    }
}

impl Acceptable for ChannelListener {
    type Output = ChannelStream;

    fn accept_connection(&mut self) -> AcceptableResult<Self::Output> {
        Box::pin(async move {
            let (byte_writer, sender) = match self.rx.recv().await {
                Some((first, second)) => (first, second),
                None => return Err(io::Error::from(ConnectionRefused)),
            };

            let (tx, byte_reader) = channel(10);
            let stream = ChannelStream::new(byte_writer, byte_reader);

            if sender.send(tx).await.is_err() {
                return Err(io::Error::from(ConnectionRefused));
            }

            Ok((stream, SocketAddr::new("127.0.0.1".parse().unwrap(), 0)))
        })
    }
}
