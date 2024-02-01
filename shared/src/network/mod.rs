use extcrypto::blowfish::Blowfish;
use std::io;
use std::io::ErrorKind::ConnectionAborted;
use std::io::Result;

use crate::network::packet::sendable::SendablePacketOutput;
use crate::network::stream::Streamable;
use crate::structs::session::Session;
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

pub async fn send_packet(
    stream: &mut impl Streamable,
    packet: SendablePacketOutput,
    blowfish: &Blowfish,
    session: &Session,
) -> Result<()> {
    stream
        .send_bytes(packet.to_bytes(blowfish, session).as_slice())
        .await?;

    Ok(())
}
