use crate::network::channel::channel_stream::ChannelStream;
use std::io::ErrorKind::ConnectionRefused;
use std::io::{Error, Result};
use tokio::sync::mpsc::{channel, Sender};

pub type ChannelConnector = Sender<(Sender<Vec<u8>>, Sender<Sender<Vec<u8>>>)>;

pub async fn connect(connector: &mut ChannelConnector) -> Result<ChannelStream> {
    let (byte_writer, byte_reader) = channel::<Vec<u8>>(10);
    let (sender, mut receiver) = channel::<Sender<Vec<u8>>>(10);

    if let Err(_) = connector.send((byte_writer, sender)).await {
        return Err(Error::from(ConnectionRefused));
    }

    let remote_writer = match receiver.recv().await {
        Some(writer) => writer,
        None => return Err(Error::from(ConnectionRefused)),
    };

    let stream = ChannelStream::new(remote_writer, byte_reader);

    Ok(stream)
}
