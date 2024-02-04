use crate::packet::handlers::auth_gameguard::handle_gameguard_auth;
use crate::packet::handlers::login_credentials::handle_login_credentials;
use crate::packet::server::login_fail::{LoginFailPacket, LoginFailReason};
use crate::packet::server::{handle_packet, InitPacket, ServerPacketBytes};
use shared::crypto::blowfish::{encrypt_packet, StaticL2Blowfish};
use shared::extcrypto::blowfish::Blowfish;
use shared::network::listener::Acceptable;
use shared::network::send_packet;
use shared::network::stream::Streamable;
use shared::structs::session::ServerSession;
use shared::tokio;
use shared::tokio::select;
use shared::tokio::sync::broadcast::Sender;
use shared::tokio::sync::{broadcast, Mutex};
use std::collections::HashMap;
use std::io::{
    ErrorKind::{AlreadyExists, ConnectionAborted, Unsupported},
    Result,
};
use std::net::SocketAddr;
use std::sync::Arc;

#[derive(Clone, Debug)]
pub enum MessageAction {
    Disconnect,
}

pub type AccountsList = Arc<Mutex<HashMap<String, Sender<(MessageAction, Vec<u8>)>>>>;

pub async fn start_server(mut listener: impl Acceptable) -> Result<()> {
    let clients: AccountsList = Arc::new(Mutex::new(HashMap::<
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
    clients: AccountsList,
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
        lock.insert(account.clone(), sender);
        println!("Clients: {}", lock.len());

        lock.get(&account).unwrap().subscribe()
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
