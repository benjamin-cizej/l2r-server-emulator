use loginserver::packet::client::{ClientPacketOutput, FromDecryptedPacket};
use loginserver::packet::server::InitPacket;
use shared::crypto::blowfish::{decrypt_packet, encrypt_packet, StaticL2Blowfish};
use shared::extcrypto::blowfish::Blowfish;
use shared::network::channel::channel_connection::{connect, ChannelConnector};
use shared::network::channel::channel_stream::ChannelStream;
use shared::network::stream::Streamable;
use shared::network::{read_packet, send_packet};
use shared::structs::session::ClientSession;
use shared::tokio::io;
use shared::tokio::net::{TcpStream, ToSocketAddrs};
use std::io::{Error, ErrorKind};
use std::net::SocketAddr;

pub struct Client<T>
where
    T: Streamable,
{
    pub connection: T,
    bytes: Vec<u8>,
    pub session: Option<ClientSession>,
}

impl<T> Client<T>
where
    T: Streamable,
{
    pub fn new(stream: T) -> Self
    where
        T: Streamable,
    {
        Client {
            connection: stream,
            bytes: vec![],
            session: None,
        }
    }

    pub async fn connect_tcp<A: ToSocketAddrs>(addr: A) -> Client<TcpStream> {
        let stream = TcpStream::connect(addr).await.unwrap();

        Client {
            connection: stream,
            bytes: vec![],
            session: None,
        }
    }

    pub async fn connect_channel(connector: &mut ChannelConnector) -> Client<ChannelStream> {
        let stream = connect(connector).await.unwrap();

        Client {
            connection: stream,
            bytes: vec![],
            session: None,
        }
    }

    pub fn get_last_bytes_received(&self) -> &Vec<u8> {
        &self.bytes
    }

    pub async fn read_init_packet(&mut self, addr: SocketAddr) -> io::Result<InitPacket> {
        let mut packet = read_packet(&mut self.connection).await?;
        decrypt_packet(&mut packet, &Blowfish::new_static());
        self.bytes = packet.clone();
        let packet = InitPacket::from_decrypted_packet(packet, None)?;
        self.session = Some(packet.to_client_session(addr));

        InitPacket::from_decrypted_packet(self.bytes.clone(), None)
    }

    pub async fn read_packet(&mut self) -> io::Result<Vec<u8>> {
        let mut packet = read_packet(&mut self.connection).await?;
        let session = self.get_session_or_err()?;
        decrypt_packet(&mut packet, &Blowfish::new(&session.blowfish_key));
        self.bytes = packet.clone();

        Ok(packet)
    }

    pub async fn send_packet(&mut self, packet: ClientPacketOutput) -> io::Result<()> {
        let session = self.get_session_or_err()?;
        let mut packet = packet.to_bytes(Some(session))?;
        encrypt_packet(&mut packet, &Blowfish::new(&session.blowfish_key));
        send_packet(&mut self.connection, packet).await?;

        Ok(())
    }

    fn get_session_or_err(&self) -> io::Result<&ClientSession> {
        match &self.session {
            Some(session) => Ok(session),
            None => Err(Error::new(
                ErrorKind::NotFound,
                "No session found in client.",
            )),
        }
    }
}
