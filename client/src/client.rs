use shared::network::channel::channel_connection::{connect, ChannelConnector};
use shared::network::channel::channel_stream::ChannelStream;
use shared::network::stream::Streamable;
use shared::network::{read_packet, send_packet};
use shared::tokio::io;
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

    pub async fn read_packet(&mut self) -> io::Result<Vec<u8>> {
        let packet = read_packet(&mut self.connection).await?;
        self.bytes = packet.clone();

        Ok(packet)
    }

    pub async fn send_packet(&mut self, packet: Vec<u8>) -> io::Result<()> {
        send_packet(&mut self.connection, packet).await?;

        Ok(())
    }
}
