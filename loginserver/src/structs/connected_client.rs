use crate::packet::server::ServerPacketOutput;
use crate::structs::connected_client::ConnectionState::Connected;
use shared::crypto::blowfish::{decrypt_packet, encrypt_packet};
use shared::extcrypto::blowfish::Blowfish;
use shared::network::stream::Streamable;
use shared::network::{read_packet, send_packet};
use shared::structs::session::ServerSession;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;

pub enum ConnectionState {
    Connected,
    GameGuardAuthorization,
    GameGuardAuthorized,
    CredentialsAuthorization,
    Authorized,
    Disconnected,
}

pub struct ConnectedClient<T>
where
    T: Streamable,
{
    pub stream: T,
    pub session: ServerSession,
    pub state: ConnectionState,
}

impl<T> ConnectedClient<T>
where
    T: Streamable,
{
    pub fn new(stream: T, addr: SocketAddr) -> Self {
        ConnectedClient {
            stream,
            session: ServerSession::new(addr),
            state: Connected,
        }
    }
}

impl<T> LoginClientPackets for ConnectedClient<T>
where
    T: Streamable,
{
    fn send_packet<'a>(
        &'a mut self,
        packet: ServerPacketOutput,
    ) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + 'a>> {
        Box::pin(async move {
            let mut bytes = packet.to_bytes(Some(&self.session))?;
            encrypt_packet(&mut bytes, &Blowfish::new(&self.session.blowfish_key));
            send_packet(&mut self.stream, bytes).await
        })
    }

    fn read_packet<'a>(
        &'a mut self,
    ) -> Pin<Box<dyn Future<Output = io::Result<Vec<u8>>> + Send + 'a>> {
        Box::pin(async move {
            let mut bytes = read_packet(&mut self.stream).await?;
            decrypt_packet(&mut bytes, &Blowfish::new(&self.session.blowfish_key));
            Ok(bytes)
        })
    }
}

pub trait LoginClientPackets {
    fn send_packet<'a>(
        &'a mut self,
        packet: ServerPacketOutput,
    ) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + 'a>>;

    fn read_packet<'a>(
        &'a mut self,
    ) -> Pin<Box<dyn Future<Output = io::Result<Vec<u8>>> + Send + 'a>>;
}
