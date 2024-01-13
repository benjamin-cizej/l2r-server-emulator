use std::error::Error;
use std::io::ErrorKind;
use std::net::SocketAddr;

use shared::extcrypto::blowfish::Blowfish;
use shared::network::send_packet;
use shared::structs::session::Session;
use shared::tokio;
use shared::tokio::net::{TcpListener, TcpStream};

use crate::packet::client::handle_packet;
use crate::packet::server::InitPacket;

mod packet;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let login_server = TcpListener::bind("127.0.0.1:2106").await?;

    loop {
        let (stream, addr) = match login_server.accept().await {
            Err(e) => {
                println!("Connection could not be established: {:?}", e);
                continue;
            }
            Ok((stream, addr)) => (stream, addr),
        };

        println!("Connection established from {:?}", addr);
        stream.set_nodelay(true).unwrap();
        tokio::spawn(async move { handle_stream(stream, addr).await });
    }
}

async fn handle_stream(mut stream: TcpStream, addr: SocketAddr) {
    let session = Session::new();
    let blowfish = Blowfish::new(&session.blowfish_key);
    if let Err(e) = send_packet(&mut stream, Box::new(InitPacket::new(&session))).await {
        println!("Error sending initial packet: {:?}", e);
        return;
    }

    loop {
        if let Err(e) = handle_packet(&mut stream, &blowfish).await {
            match e.kind() {
                ErrorKind::Unsupported => {
                    println!("Unknown packet received: {}", e.to_string());
                    continue;
                }
                ErrorKind::ConnectionAborted => {
                    println!("Connection closed from {:?}", addr);
                    return;
                }
                _ => {
                    println!("Connection terminated with an error: {:?}", e);
                    return;
                }
            }
        }
    }
}
