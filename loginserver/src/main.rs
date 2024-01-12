use shared::extcrypto::blowfish::Blowfish;
use shared::network::send_packet;
use shared::structs::server::Server;
use shared::structs::session::Session;
use shared::tokio;
use shared::tokio::net::{TcpListener, TcpStream};
use std::error::Error;
use std::net::Ipv4Addr;

use crate::packet::client::{
    decrypt_packet, AuthGameGuardPacket, FromDecryptedPacket, PacketTypeEnum,
};
use crate::packet::server::{
    GGAuthPacket, InitPacket, LoginOkPacket, PlayOkPacket, ServerListPacket,
};
use shared::network::serverpacket::ServerPacketOutput;

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
        tokio::spawn(async move { handle_stream(stream).await });
    }
}

async fn handle_stream(mut stream: TcpStream) {
    let session = Session::new();
    let blowfish = Blowfish::new(&session.blowfish_key);
    send_packet(&mut stream, Box::new(InitPacket::new(&session))).await;

    loop {
        let decrypted_packet = match decrypt_packet(&mut stream, &blowfish).await {
            Err(e) => {
                println!("Login server connection error: {:?}", e);
                return;
            }
            Ok(packet) => packet,
        };

        let packet_type = match PacketTypeEnum::from_packet(&decrypted_packet) {
            None => {
                println!(
                    "Unknown packet received: {:02x?}",
                    decrypted_packet.get(0).unwrap()
                );
                continue;
            }
            Some(packet_type) => packet_type,
        };

        let matched_packet: Box<dyn ServerPacketOutput + Send> = match packet_type {
            PacketTypeEnum::RequestAuthLogin => Box::new(LoginOkPacket::new(&blowfish)),
            PacketTypeEnum::AuthGameGuard => {
                let packet = AuthGameGuardPacket::from_decrypted_packet(decrypted_packet);
                let session_id = packet.get_session_id();
                let mut packet = GGAuthPacket::new(&blowfish);
                packet.session_id = session_id;

                Box::new(packet)
            }
            PacketTypeEnum::ServerList => {
                let mut packet = ServerListPacket::new(&blowfish);
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
            PacketTypeEnum::RequestServerLogin => Box::new(PlayOkPacket::new(&blowfish)),
        };

        send_packet(&mut stream, matched_packet).await;
    }
}
