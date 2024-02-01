use loginserver::packet::client::{decrypt_packet, FromDecryptedPacket};
use shared::extcrypto::blowfish::Blowfish;
use shared::network::channel::channel_connection::{connect, ChannelConnector};
use shared::network::channel::channel_stream::ChannelStream;
use shared::network::packet::sendable::SendablePacketOutput;
use shared::network::stream::Streamable;
use shared::network::{read_packet, send_packet};
use shared::structs::session::Session;
use shared::tokio::net::{TcpStream, ToSocketAddrs};

pub struct Client<T>
where
    T: Streamable,
{
    pub connection: T,
    bytes: Vec<u8>,
}

impl<T> Client<T>
where
    T: Streamable,
{
    pub async fn connect_tcp<A: ToSocketAddrs>(addr: A) -> Client<TcpStream> {
        let stream = TcpStream::connect(addr).await.unwrap();

        Client {
            connection: stream,
            bytes: vec![],
        }
    }

    pub async fn connect_channel(connector: &mut ChannelConnector) -> Client<ChannelStream> {
        let stream = connect(connector).await.unwrap();

        Client {
            connection: stream,
            bytes: vec![],
        }
    }

    pub fn get_last_bytes_received(&self) -> &Vec<u8> {
        &self.bytes
    }

    pub async fn read_packet<P>(&mut self, blowfish: &Blowfish) -> P
    where
        P: FromDecryptedPacket,
    {
        let packet = read_packet(&mut self.connection).await.unwrap();
        let decrypted_packet = decrypt_packet(packet, &blowfish);
        self.bytes = decrypted_packet.clone();

        P::from_decrypted_packet(decrypted_packet)
    }

    pub async fn send_packet(
        &mut self,
        packet: SendablePacketOutput,
        blowfish: &Blowfish,
        session: &Session,
    ) {
        send_packet(&mut self.connection, packet, blowfish, session)
            .await
            .unwrap();
    }
}
