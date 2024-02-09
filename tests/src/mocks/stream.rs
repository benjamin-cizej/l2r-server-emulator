use shared::network::stream::Streamable;
use std::future::Future;
use std::io::Write;
use std::pin::Pin;

pub struct MockStream {
    buffer: Vec<u8>,
}

impl MockStream {
    pub fn new(buffer: Vec<u8>) -> Self {
        MockStream { buffer }
    }
}

impl Streamable for MockStream {
    fn send_bytes<'a>(
        &'a mut self,
        buf: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = std::io::Result<()>> + Send + 'a>> {
        Box::pin(async move {
            self.buffer.clone_from(&buf.to_vec());
            Ok(())
        })
    }

    fn receive_bytes<'a>(
        &'a mut self,
        mut buf: &'a mut [u8],
    ) -> Pin<Box<dyn Future<Output = std::io::Result<usize>> + Send + 'a>> {
        Box::pin(async move {
            if self.buffer.is_empty() {
                return Ok(0);
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
