use crate::crypto::dec_xor_pass;
use loginserver::packet::client::FromDecryptedPacket;
use loginserver::packet::server::InitPacket;
use shared::crypto::decrypt_packet;
use shared::extcrypto::blowfish::Blowfish;
use shared::network::channel::channel_connection::{connect, ChannelConnector};
use shared::network::channel::channel_stream::ChannelStream;
use shared::network::read_packet;
use shared::network::stream::Streamable;
use shared::tokio::net::{TcpStream, ToSocketAddrs};

pub struct Client<T>
where
    T: Streamable,
{
    pub connection: T,
    packet: Vec<u8>,
}

impl<T> Client<T>
where
    T: Streamable,
{
    pub async fn connect_tcp<A: ToSocketAddrs>(addr: A) -> Client<TcpStream> {
        let stream = TcpStream::connect(addr).await.unwrap();

        Client {
            connection: stream,
            packet: vec![],
        }
    }

    pub async fn connect_channel(connector: &mut ChannelConnector) -> Client<ChannelStream> {
        let stream = connect(connector).await.unwrap();

        Client {
            connection: stream,
            packet: vec![],
        }
    }

    pub fn get_last_packet_received(&self) -> &Vec<u8> {
        &self.packet
    }

    pub async fn read_init_packet(&mut self) -> InitPacket {
        let blowfish = Blowfish::new(&[
            0x6b, 0x60, 0xcb, 0x5b, 0x82, 0xce, 0x90, 0xb1, 0xcc, 0x2b, 0x6c, 0x55, 0x6c, 0x6c,
            0x6c, 0x6c,
        ]);

        let packet = read_packet(&mut self.connection).await.unwrap();
        let mut packet = decrypt_packet(packet, &blowfish);
        let packet_len = packet.len();
        let key_start_index = packet_len - 8;
        let key_end_index = packet_len - 4;
        let key = packet.get(key_start_index..key_end_index).unwrap();
        let key = u32::from_le_bytes(key.try_into().unwrap());
        dec_xor_pass(&mut packet, 0, packet_len, key).unwrap();

        self.packet = packet.to_vec();

        InitPacket::from_decrypted_packet(packet)
    }
}
