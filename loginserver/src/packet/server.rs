use shared::tokio::io::AsyncWriteExt;
use shared::tokio::net::TcpStream;

pub mod login;

pub trait ServerPacketOutput {
    fn to_output_stream(&self) -> Vec<u8>;
}

pub async fn send_packet(stream: &mut TcpStream, packet: Box<dyn ServerPacketOutput + Send>) {
    stream
        .write(packet.to_output_stream().as_slice())
        .await
        .unwrap();
    stream.flush().await.unwrap();
}
