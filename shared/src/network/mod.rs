use std::io;
use std::io::ErrorKind::ConnectionAborted;
use std::io::Result;

use crate::network::packet::prepend_length;
use crate::network::stream::Streamable;
use num::ToPrimitive;

pub mod channel;
pub mod listener;
pub mod packet;
pub mod stream;
pub mod tcp;

pub async fn read_packet(stream: &mut impl Streamable) -> Result<Vec<u8>> {
    let mut len = [0u8; 2];
    let bytes_read = stream.receive_bytes(&mut len).await?;
    if bytes_read == 0 {
        return Err(io::Error::from(ConnectionAborted));
    }

    let mut data = vec![0; u16::from_le_bytes(len).to_usize().unwrap() - 2];
    stream.receive_bytes(&mut data).await?;

    Ok(data)
}

pub async fn send_packet(stream: &mut impl Streamable, mut packet: Vec<u8>) -> Result<()> {
    prepend_length(&mut packet);
    stream.send_bytes(packet.as_slice()).await?;

    Ok(())
}
