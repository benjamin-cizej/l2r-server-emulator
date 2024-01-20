use crate::network::channel::channel_stream::ChannelStream;
use std::io;
use std::io::ErrorKind::ConnectionRefused;
use tokio::sync::mpsc::Sender;

async fn connect(
    connector: &mut Sender<(Sender<Vec<u8>>, Sender<Sender<Vec<u8>>>)>,
) -> io::Result<ChannelStream> {
    let (byte_writer, byte_reader) = tokio::sync::mpsc::channel::<Vec<u8>>(10);
    let (sender, mut receiver) = tokio::sync::mpsc::channel::<Sender<Vec<u8>>>(10);

    if let Err(_) = connector.send((byte_writer, sender)).await {
        return Err(io::Error::from(ConnectionRefused));
    }

    let remote_writer = match receiver.recv().await {
        Some(writer) => writer,
        None => return Err(io::Error::from(ConnectionRefused)),
    };

    let stream = ChannelStream::build(remote_writer, byte_reader);

    Ok(stream)
}
