use crate::network::serverpacket::ServerPacketOutput;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

pub mod serverpacket;

pub async fn send_packet(stream: &mut TcpStream, packet: Box<dyn ServerPacketOutput + Send>) {
    stream
        .write(packet.to_output_stream().as_slice())
        .await
        .unwrap();
    stream.flush().await.unwrap();
}
