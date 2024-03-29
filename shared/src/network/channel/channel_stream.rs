use crate::network::stream::Streamable;
use std::future::Future;
use std::io;
use std::io::ErrorKind::ConnectionReset;
use std::io::Write;
use std::pin::Pin;
use tokio::sync::mpsc::{Receiver, Sender};

pub struct ChannelStream {
    tx: Sender<Vec<u8>>,
    rx: Receiver<Vec<u8>>,
    buffer: Vec<u8>,
}

impl ChannelStream {
    pub fn new(tx: Sender<Vec<u8>>, rx: Receiver<Vec<u8>>) -> Self {
        ChannelStream {
            tx,
            rx,
            buffer: vec![],
        }
    }

    pub fn new_connected_pair() -> (Self, Self) {
        let (tx1, rx1) = tokio::sync::mpsc::channel::<Vec<u8>>(10);
        let (tx2, rx2) = tokio::sync::mpsc::channel::<Vec<u8>>(10);

        let stream1 = ChannelStream::new(tx1, rx2);
        let stream2 = ChannelStream::new(tx2, rx1);

        (stream1, stream2)
    }
}

impl Streamable for ChannelStream {
    fn send_bytes<'a>(
        &'a mut self,
        buf: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + 'a>> {
        let bytes = buf.to_owned();
        Box::pin(async move {
            match self.tx.send(bytes).await {
                Err(_) => Err(io::Error::from(ConnectionReset)),
                _ => Ok(()),
            }
        })
    }

    fn receive_bytes<'a>(
        &'a mut self,
        mut buf: &'a mut [u8],
    ) -> Pin<Box<dyn Future<Output = io::Result<usize>> + Send + 'a>> {
        Box::pin(async move {
            if self.buffer.is_empty() {
                self.buffer = match self.rx.recv().await {
                    Some(buffer) => buffer,
                    None => return Ok(0),
                };
            }

            let mut read_length = buf.len();
            if read_length > self.buffer.len() {
                read_length = self.buffer.len();
            }

            let (first, second) = self.buffer.split_at(read_length);
            buf.write_all(first)?;
            self.buffer = second.to_vec();

            Ok(read_length)
        })
    }
}
