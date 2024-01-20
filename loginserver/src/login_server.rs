use std::collections::HashMap;
use std::error::Error;
use std::io::ErrorKind::{AlreadyExists, ConnectionAborted, InvalidData, Unsupported};
use std::net::SocketAddr;
use std::sync::Arc;

use shared::extcrypto::blowfish::Blowfish;
use shared::network::listener::Acceptable;
use shared::network::serverpacket::ServerPacketOutput;
use shared::network::stream::Streamable;
use shared::network::{read_packet, send_packet};
use shared::structs::session::Session;
use shared::tokio;
use shared::tokio::select;
use shared::tokio::sync::broadcast::Sender;
use shared::tokio::sync::{broadcast, Mutex};

use crate::packet::client::{
    decrypt_packet, handle_packet, AuthGameGuardPacket, FromDecryptedPacket, PacketTypeEnum,
    RequestAuthLoginPacket,
};
use crate::packet::server::login_fail::{LoginFailPacket, LoginFailReason};
use crate::packet::server::{GGAuthPacket, InitPacket, LoginOkPacket};

#[derive(Clone, Debug)]
pub enum MessageAction {
    Disconnect,
}

pub async fn start_server(listener: impl Acceptable) -> Result<(), Box<dyn Error>> {
    let clients = Arc::new(Mutex::new(HashMap::<
        String,
        Sender<(MessageAction, Vec<u8>)>,
    >::new()));

    loop {
        let (stream, addr) = match listener.accept_connection().await {
            Err(e) => {
                println!("Connection could not be established: {:?}", e);
                continue;
            }
            Ok((stream, addr)) => (stream, addr),
        };

        let (client_tx, _) = broadcast::channel::<(MessageAction, Vec<u8>)>(10);

        println!("Connection established from {:?}", addr);
        let cloned_clients = clients.clone();
        tokio::spawn(async move {
            handle_stream(stream, addr, client_tx.clone(), cloned_clients).await
        });
    }
}

async fn handle_stream(
    mut stream: impl Streamable,
    addr: SocketAddr,
    sender: Sender<(MessageAction, Vec<u8>)>,
    clients: Arc<Mutex<HashMap<String, Sender<(MessageAction, Vec<u8>)>>>>,
) {
    let session = Session::new();
    let blowfish = Blowfish::new(&session.blowfish_key);
    if let Err(e) = send_packet(&mut stream, Box::new(InitPacket::new(&session))).await {
        println!("Error sending initial packet: {:?}", e);
        return;
    }

    if let Err(e) = handle_gameguard_auth(&mut stream, &blowfish).await {
        println!("Error handling gameguard packet: {:?}", e);
        return;
    }

    let account = match handle_login_credentials(&mut stream, &blowfish, &session, &clients).await {
        Ok(account) => account,
        Err(e) => match e.kind() {
            AlreadyExists => {
                println!("Account with that username is already connected");
                println!("Connection terminated.");
                return;
            }
            _ => {
                println!("Error handling login credentials: {:?}", e);
                return;
            }
        },
    };

    println!("Account {} connected", account);

    let mut receiver = {
        let mut lock = clients.lock().await;
        lock.insert(account.clone(), sender.clone());
        println!("Clients: {}", lock.len());

        lock.get(&account).unwrap().clone().subscribe()
    };

    loop {
        select! {
            result = handle_packet(&mut stream, &blowfish) => {
                if let Err(e) = &result {
                    match e.kind() {
                        Unsupported => {
                            println!("Unknown packet received: {}", e.to_string());
                            continue;
                        }
                        ConnectionAborted => {
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
            result = receiver.recv() => {
                match &result {
                    Ok((action, _)) => {
                        match action {
                            MessageAction::Disconnect => {
                                let packet = Box::new(LoginFailPacket::new(LoginFailReason::AccountInUse, &blowfish));
                                send_packet(&mut stream, packet).await.unwrap();
                                println!("Connection terminated.");
                                {
                                    clients.lock().await.remove(&account);
                                }
                                return;
                            },
                        }
                    },
                    Err(_) => {}
                }
            }
        }
    }
}

async fn handle_gameguard_auth(
    stream: &mut impl Streamable,
    blowfish: &Blowfish,
) -> std::io::Result<()> {
    let packet = read_packet(stream).await?;
    let decrypted_packet = decrypt_packet(packet, &blowfish);
    println!("decrypted");
    let packet: ServerPacketOutput = match PacketTypeEnum::from_packet(&decrypted_packet) {
        None => {
            return Err(std::io::Error::new(
                Unsupported,
                format!("0x{:02X}", decrypted_packet.get(0).unwrap()),
            ));
        }
        Some(PacketTypeEnum::AuthGameGuard) => {
            let packet = AuthGameGuardPacket::from_decrypted_packet(decrypted_packet);
            let session_id = packet.get_session_id();
            let mut packet = GGAuthPacket::new(&blowfish);
            packet.session_id = session_id;

            Box::new(packet)
        }
        Some(_) => {
            return Err(std::io::Error::new(
                InvalidData,
                "Did not receive AuthGameGuard packet",
            ));
        }
    };

    send_packet(stream, packet).await?;

    Ok(())
}

async fn handle_login_credentials(
    stream: &mut impl Streamable,
    blowfish: &Blowfish,
    session: &Session,
    accounts: &Arc<Mutex<HashMap<String, Sender<(MessageAction, Vec<u8>)>>>>,
) -> std::io::Result<String> {
    let packet = read_packet(stream).await?;
    let mut decrypted_packet = decrypt_packet(packet, &blowfish);
    let account: String;
    let packet: ServerPacketOutput = match PacketTypeEnum::from_packet(&decrypted_packet) {
        None => {
            return Err(std::io::Error::new(
                Unsupported,
                format!("0x{:02X}", decrypted_packet.get(0).unwrap()),
            ));
        }
        Some(PacketTypeEnum::RequestAuthLogin) => {
            RequestAuthLoginPacket::decrypt_credentials(&mut decrypted_packet, &session)?;
            let packet = RequestAuthLoginPacket::from_decrypted_packet(decrypted_packet);
            account = packet.get_username();
            println!("dec acc {}", account);
            if let Some(sender) = accounts.lock().await.get(&account) {
                let packet: ServerPacketOutput = Box::new(LoginFailPacket::new(
                    LoginFailReason::AccountInUse,
                    &blowfish,
                ));
                sender
                    .send((MessageAction::Disconnect, packet.to_output_stream()))
                    .unwrap();
                return Err(std::io::Error::from(AlreadyExists));
            }

            Box::new(LoginOkPacket::new(&blowfish))
        }
        Some(_) => {
            return Err(std::io::Error::new(
                InvalidData,
                "Did not receive RequestAuthLogin packet",
            ));
        }
    };

    send_packet(stream, packet).await?;

    Ok(account)
}
