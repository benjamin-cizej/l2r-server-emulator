use std::io;
use std::io::ErrorKind::ConnectionAborted;
use std::io::Result;

use crate::network::serverpacket::ServerPacketOutput;
use crate::network::stream::Streamable;
use num::ToPrimitive;

pub mod listener;
pub mod serverpacket;
pub mod stream;
pub mod tokio_tcp_listener;
pub mod tokio_tcp_stream;

pub async fn read_packet(stream: &mut impl Streamable) -> Result<Vec<u8>> {
    let mut len = [0u8; 2];
    let bytes_read = stream.receive_bytes(&mut len).await?;
    if bytes_read == 0 {
        return Err(io::Error::from(ConnectionAborted));
    }

    let mut data = vec![0; u16::from_le_bytes(len).to_usize().unwrap()];
    stream.receive_bytes(&mut data).await?;

    Ok(data)
}

pub async fn send_packet(stream: &mut impl Streamable, packet: ServerPacketOutput) -> Result<()> {
    stream
        .send_bytes(packet.to_output_stream().as_slice())
        .await?;

    Ok(())
}
