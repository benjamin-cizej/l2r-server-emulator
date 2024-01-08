use shared::extcrypto::blowfish::Blowfish;
use shared::structs::server::Server;
use shared::structs::session::Session;
use std::io::ErrorKind;
use std::net::Ipv4Addr;
use std::{
    net::{TcpListener, TcpStream},
    thread, time,
};

use crate::packet::client::login::RequestAuthLoginPacket;
use crate::packet::client::{decrypt_login_packet, FromDecryptedPacket, LoginClientPacketEnum};
use crate::packet::server::login::{InitPacket, LoginOkPacket, PlayOkPacket, ServerListPacket};
use crate::packet::server::{send_packet, ServerPacketOutput};
use crate::packet::{client, server};

mod packet;

fn main() -> std::io::Result<()> {
    let login_server = TcpListener::bind("127.0.0.1:2106")?;
    for stream in login_server.incoming() {
        if let Ok(stream) = stream {
            println!("Login server connection established");
            stream.set_nodelay(true).unwrap();
            stream.set_nonblocking(true).unwrap();
            thread::spawn(move || handle_stream(stream.try_clone().unwrap()));
        }
    }

    Ok(())
}

fn handle_stream(mut stream: TcpStream) {
    let session = Session::new();
    let blowfish = Blowfish::new(&session.blowfish_key);
    send_packet(&mut stream, Box::new(InitPacket::new(&session)));

    'main: loop {
        thread::sleep(time::Duration::from_millis(10));

        loop {
            match decrypt_login_packet(&mut stream, &blowfish) {
                Ok(mut decrypted_packet) => {
                    if let Some(packet_type) = LoginClientPacketEnum::from_packet(&decrypted_packet)
                    {
                        let matched_packet: Box<dyn ServerPacketOutput>;
                        match packet_type {
                            LoginClientPacketEnum::RequestAuthLogin => {
                                RequestAuthLoginPacket::decrypt_credentials(
                                    &mut decrypted_packet,
                                    &session,
                                );
                                let packet =
                                    RequestAuthLoginPacket::from_decrypted_packet(decrypted_packet);
                                println!("Packet: {:?}", packet);

                                matched_packet = Box::new(LoginOkPacket::new(&blowfish));
                            }
                            LoginClientPacketEnum::AuthGameGuard => {
                                let packet =
                                    client::login::AuthGameGuardPacket::from_decrypted_packet(
                                        decrypted_packet,
                                    );
                                let session_id = packet.get_session_id();
                                let mut packet = server::login::AuthGameGuardPacket::new(&blowfish);
                                packet.session_id = session_id;
                                matched_packet = Box::new(packet);
                            }
                            LoginClientPacketEnum::ServerList => {
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
                                matched_packet = Box::new(packet)
                            }
                            LoginClientPacketEnum::RequestServerLogin => {
                                matched_packet = Box::new(PlayOkPacket::new(&blowfish));
                            }
                        }

                        send_packet(&mut stream, matched_packet);
                    } else {
                        println!(
                            "Unknown packet received: {:02x?}",
                            decrypted_packet.get(0).unwrap()
                        );
                    }
                }
                Err(e) => match e.kind() {
                    ErrorKind::ConnectionAborted
                    | ErrorKind::UnexpectedEof
                    | ErrorKind::ConnectionReset => {
                        break 'main;
                    }
                    _ => {
                        break;
                    }
                },
            }
        }
    }

    println!("Login server connection terminated");
}
