use std::io;
use std::io::ErrorKind::ConnectionAborted;
use std::io::Result;

use num::ToPrimitive;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::network::serverpacket::ServerPacketOutput;

pub mod serverpacket;

pub async fn read_packet(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut len = [0u8; 2];
    let bytes_read = stream.read_exact(&mut len).await?;
    if bytes_read == 0 {
        return Err(io::Error::from(ConnectionAborted));
    }

    let mut data = vec![0; u16::from_le_bytes(len).to_usize().unwrap()];
    stream.read(&mut data).await?;

    Ok(data)
}

pub async fn send_packet(stream: &mut TcpStream, packet: ServerPacketOutput) -> Result<()> {
    stream
        .write_all(packet.to_output_stream().as_slice())
        .await?;
    stream.flush().await?;

    Ok(())
}
