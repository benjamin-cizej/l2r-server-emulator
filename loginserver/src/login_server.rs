use shared::crypto::blowfish::{decrypt_packet, encrypt_packet, StaticL2Blowfish};
use shared::extcrypto::blowfish::Blowfish;
use shared::network::listener::Acceptable;
use shared::network::stream::Streamable;
use shared::network::{read_packet, send_packet};
use shared::structs::session::ServerSession;
use shared::tokio;
use shared::tokio::select;
use shared::tokio::sync::broadcast::Sender;
use shared::tokio::sync::{broadcast, Mutex};
use std::collections::HashMap;
use std::io::{
    ErrorKind::{AlreadyExists, ConnectionAborted, InvalidData, Unsupported},
    Result,
};
use std::net::SocketAddr;
use std::sync::Arc;

use crate::packet::client::{PacketTypeEnum, RequestAuthLoginPacket};
use crate::packet::handlers::auth_gameguard::handle_gameguard_auth;
use crate::packet::server::login_fail::{LoginFailPacket, LoginFailReason};
use crate::packet::server::{
    handle_packet, FromDecryptedPacket, InitPacket, LoginOkPacket, ServerPacketBytes,
    ServerPacketOutput,
};

#[derive(Clone, Debug)]
pub enum MessageAction {
    Disconnect,
}

pub async fn start_server(mut listener: impl Acceptable) -> Result<()> {
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
    let session = ServerSession::new(addr);
    let mut packet = InitPacket::new(&session).to_bytes(None).unwrap();
    encrypt_packet(&mut packet, &Blowfish::new_static());
    if let Err(e) = send_packet(&mut stream, packet).await {
        println!("Error sending initial packet: {:?}", e);
        return;
    }

    if let Err(e) = handle_gameguard_auth(&mut stream, &session).await {
        println!("Error handling gameguard packet: {:?}", e);
        return;
    }

    let account = match handle_login_credentials(&mut stream, &session, &clients).await {
        Ok(account) => account,
        Err(e) => match e.kind() {
            AlreadyExists => {
                println!("Account with that username is already connected");
                println!("Connection terminated for {}.", addr);
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
            result = handle_packet(&mut stream, &session) => {
                if let Err(e) = &result {
                    match e.kind() {
                        Unsupported => {
                            println!("Unknown packet received: {}", e.to_string());
                            continue;
                        }
                        ConnectionAborted => {
                            clients.lock().await.remove(&account);
                            println!("Connection closed from {:?}", addr);
                            return;
                        }
                        _ => {
                            clients.lock().await.remove(&account);
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
                                let mut packet = LoginFailPacket::new(LoginFailReason::AccountInUse).to_bytes(None).unwrap();
                                encrypt_packet(&mut packet, &Blowfish::new(&session.blowfish_key));
                                send_packet(&mut stream, packet).await.unwrap();
                                println!("Connection terminated for {:?}.", addr);
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

async fn handle_login_credentials(
    stream: &mut impl Streamable,
    session: &ServerSession,
    accounts: &Arc<Mutex<HashMap<String, Sender<(MessageAction, Vec<u8>)>>>>,
) -> Result<String> {
    let mut packet = read_packet(stream).await?;
    decrypt_packet(&mut packet, &Blowfish::new(&session.blowfish_key));
    let account: String;
    let mut packet = match PacketTypeEnum::from_packet(&packet) {
        None => {
            return Err(std::io::Error::new(
                Unsupported,
                format!("0x{:02X}", packet.get(0).unwrap()),
            ));
        }
        Some(PacketTypeEnum::RequestAuthLogin) => {
            let packet = RequestAuthLoginPacket::from_decrypted_packet(packet, Some(&session))?;
            account = packet.get_username();
            if let Some(sender) = accounts.lock().await.get(&account) {
                let packet: ServerPacketOutput =
                    Box::new(LoginFailPacket::new(LoginFailReason::AccountInUse));
                sender
                    .send((MessageAction::Disconnect, packet.to_bytes(Some(&session))?))
                    .unwrap();

                let mut packet = packet.to_bytes(None).unwrap();
                encrypt_packet(&mut packet, &Blowfish::new(&session.blowfish_key));
                send_packet(stream, packet).await?;
                return Err(std::io::Error::from(AlreadyExists));
            }

            LoginOkPacket::new(0, 0).to_bytes(None)?
        }
        Some(_) => {
            return Err(std::io::Error::new(
                InvalidData,
                "Did not receive RequestAuthLogin packet",
            ));
        }
    };

    encrypt_packet(&mut packet, &Blowfish::new(&session.blowfish_key));
    send_packet(stream, packet).await?;

    Ok(account)
}
