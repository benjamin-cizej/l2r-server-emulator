use std::io::Write;
use std::net::TcpStream;

pub mod login;

pub trait ServerPacketOutput {
    fn to_output_stream(&self) -> Vec<u8>;
}

pub fn send_packet(stream: &mut TcpStream, packet: Box<dyn ServerPacketOutput>) {
    stream.write(packet.to_output_stream().as_slice()).unwrap();
    stream.flush().unwrap();
}
