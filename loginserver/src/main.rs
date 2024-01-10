use shared::extcrypto::blowfish::Blowfish;
use shared::network::send_packet;
use shared::structs::server::Server;
use shared::structs::session::Session;
use shared::tokio;
use shared::tokio::net::{TcpListener, TcpStream};
use std::error::Error;
use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddr};

use crate::packet::client::FromDecryptedPacket;
use shared::network::serverpacket::ServerPacketOutput;

mod packet;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let login_server = TcpListener::bind("127.0.0.1:2106").await?;

    loop {
        let result = login_server.accept().await;
        if let Ok(result) = result {
            let (stream, addr) = result;
            stream.set_nodelay(true).unwrap();
            println!(
                "Login server connection established from {:?}:{:?}",
                addr.ip().to_string(),
                addr.port().to_string()
            );
            tokio::spawn(async move { handle_stream(stream, addr).await });
        }
    }
}

async fn handle_stream(mut stream: TcpStream, addr: SocketAddr) {
    let session = Session::new();
    let blowfish = Blowfish::new(&session.blowfish_key);
    send_packet(
        &mut stream,
        Box::new(packet::server::InitPacket::new(&session)),
    )
    .await;

    loop {
        match packet::client::decrypt_packet(&mut stream, &blowfish).await {
            Ok(decrypted_packet) => {
                if let Some(packet_type) =
                    packet::client::PacketEnum::from_packet(&decrypted_packet)
                {
                    let matched_packet: Box<dyn ServerPacketOutput + Send> = match packet_type {
                        packet::client::PacketEnum::RequestAuthLogin => {
                            Box::new(packet::server::LoginOkPacket::new(&blowfish))
                        }
                        packet::client::PacketEnum::AuthGameGuard => {
                            let packet = packet::client::AuthGameGuardPacket::from_decrypted_packet(
                                decrypted_packet,
                            );
                            let session_id = packet.get_session_id();
                            let mut packet = packet::server::GGAuthPacket::new(&blowfish);
                            packet.session_id = session_id;

                            Box::new(packet)
                        }
                        packet::client::PacketEnum::ServerList => {
                            let mut packet = packet::server::ServerListPacket::new(&blowfish);
                            packet.list.push(Server {
                                id: 1,
                                ip: Ipv4Addr::new(127, 0, 0, 1),
                                port: 7778,
                                age_limit: false,
                                pvp_enabled: true,
                                current_players: 0,
                                max_players: 100,
                                status: true,
                                server_type: 1,
                                brackets: false,
                            });

                            Box::new(packet)
                        }
                        packet::client::PacketEnum::RequestServerLogin => {
                            Box::new(packet::server::PlayOkPacket::new(&blowfish))
                        }
                    };

                    send_packet(&mut stream, matched_packet).await;
                } else {
                    println!(
                        "Unknown packet received: {:02x?} from {:?}:{:?}",
                        decrypted_packet.get(0).unwrap(),
                        addr.ip().to_string(),
                        addr.port().to_string()
                    );
                }
            }
            Err(e) => {
                match e.kind() {
                    ErrorKind::WouldBlock => {
                        println!("Login server blocking operation");
                    }
                    _ => {
                        println!("Login server connection error: {:?}", e.kind().to_string());
                    }
                }

                return;
            }
        }
    }
}
