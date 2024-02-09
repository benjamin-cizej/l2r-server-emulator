use crate::packet::gameserver::ServerPacketBytes;
use shared::crypto::blowfish::{decrypt_packet, encrypt_packet, StaticL2Blowfish};
use shared::extcrypto::blowfish::Blowfish;
use shared::network::packet::pad_bytes;
use shared::network::stream::Streamable;
use shared::network::{read_packet, send_packet};
use std::future::Future;
use std::io;
use std::pin::Pin;

pub struct ConnectedGameServer<T>
where
    T: Streamable,
{
    stream: T,
    pub blowfish: Blowfish,
}

impl<T> ConnectedGameServer<T>
where
    T: Streamable,
{
    pub fn new(stream: T) -> Self {
        ConnectedGameServer {
            stream,
            blowfish: Blowfish::new_static(),
        }
    }
}

impl<T> GameserverClientPacket for ConnectedGameServer<T>
where
    T: Streamable,
{
    fn send_packet<'a>(
        &'a mut self,
        packet: Box<dyn ServerPacketBytes + Send>,
    ) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + 'a>> {
        Box::pin(async move {
            let mut bytes = packet.to_bytes()?;
            pad_bytes(&mut bytes);
            encrypt_packet(&mut bytes, &self.blowfish);
            send_packet(&mut self.stream, bytes).await
        })
    }

    fn read_packet<'a>(
        &'a mut self,
    ) -> Pin<Box<dyn Future<Output = io::Result<Vec<u8>>> + Send + 'a>> {
        Box::pin(async move {
            let mut bytes = read_packet(&mut self.stream).await?;
            decrypt_packet(&mut bytes, &self.blowfish);
            Ok(bytes)
        })
    }
}

pub trait GameserverClientPacket {
    fn send_packet<'a>(
        &'a mut self,
        packet: Box<dyn ServerPacketBytes + Send>,
    ) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + 'a>>;

    fn read_packet<'a>(
        &'a mut self,
    ) -> Pin<Box<dyn Future<Output = io::Result<Vec<u8>>> + Send + 'a>>;
}
