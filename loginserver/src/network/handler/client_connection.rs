use crate::login_server::{ConnectedAccounts, MessageAction};
use crate::packet::handlers::auth_gameguard::handle_gameguard_auth;
use crate::packet::handlers::login_credentials::handle_login_credentials;
use crate::packet::server::login_fail::{LoginFailPacket, LoginFailReason};
use crate::packet::server::{handle_packet, InitPacket, ServerPacketBytes};
use crate::repository::account::AccountRepository;
use crate::structs::connected_client::ConnectionState::Disconnected;
use crate::structs::connected_client::{ConnectedClient, LoginClientPackets};
use shared::crypto::blowfish::{encrypt_packet, StaticL2Blowfish};
use shared::extcrypto::blowfish::Blowfish;
use shared::network::listener::Acceptable;
use shared::network::send_packet;
use shared::network::stream::Streamable;
use shared::tokio;
use shared::tokio::select;
use shared::tokio::sync::broadcast::Sender;
use shared::tokio::sync::{broadcast, Mutex};
use std::io::ErrorKind;
use std::io::ErrorKind::AlreadyExists;
use std::sync::Arc;

pub async fn handle_client_connections(
    listener: &mut impl Acceptable,
    connected_accounts: &ConnectedAccounts,
    repository: &Arc<Mutex<impl AccountRepository + Sized>>,
) {
    let (stream, addr) = match listener.accept_connection().await {
        Err(e) => {
            println!("Connection with clieent could not be established: {:?}", e);
            return;
        }
        Ok((stream, addr)) => (stream, addr),
    };
    let client = ConnectedClient::new(stream, addr);
    println!("New client connection from {:?}", addr);

    let (tx, _) = broadcast::channel::<MessageAction>(10);
    let cloned_list = connected_accounts.clone();
    let cloned_repo = repository.clone();
    tokio::spawn(async move { handle_connection(client, tx, cloned_list, cloned_repo).await });
}

async fn handle_connection(
    mut client: ConnectedClient<impl Streamable>,
    sender: Sender<MessageAction>,
    connected_accounts: ConnectedAccounts,
    repository: Arc<Mutex<impl AccountRepository>>,
) {
    let mut packet = InitPacket::new(&client.session).to_bytes(None).unwrap();
    encrypt_packet(&mut packet, &Blowfish::new_static());
    if let Err(e) = send_packet(&mut client.stream, packet).await {
        client.state = Disconnected;
        println!("Error sending initial packet: {:?}", e);
        return;
    }

    if let Err(e) = handle_gameguard_auth(&mut client).await {
        client.state = Disconnected;
        println!("Error handling gameguard packet: {:?}", e);
        return;
    }

    let account =
        match handle_login_credentials(&mut client, &connected_accounts, &repository).await {
            Ok(account) => account,
            Err(e) => {
                client.state = Disconnected;
                match e.kind() {
                    AlreadyExists => {
                        println!("Account with that username is already connected");
                        println!("Connection terminated for {}", client.session.addr);
                        return;
                    }
                    _ => {
                        println!("Error handling login credentials: {:?}", e);
                        return;
                    }
                }
            }
        };

    println!("Account {} connected", account);

    let mut receiver = {
        let mut lock = connected_accounts.lock().await;
        lock.insert(account.clone(), sender);
        lock.get(&account).unwrap().subscribe()
    };

    loop {
        select! {
            result = handle_packet(&mut client) => {
                if let Err(e) = &result {
                    match e.kind() {
                        ErrorKind::Unsupported => {
                            println!("Unknown packet received: {}", e.to_string());
                            continue;
                        }
                        ErrorKind::ConnectionAborted => {
                            connected_accounts.lock().await.remove(&account);
                            println!("Connection closed from {:?}", client.session.addr);
                            client.state = Disconnected;
                            return;
                        }
                        _ => {
                            connected_accounts.lock().await.remove(&account);
                            println!("Connection terminated with an error: {:?}", e);
                            client.state = Disconnected;
                            return;
                        }
                    }
                }
            }
            result = receiver.recv() => {
                match &result {
                    Ok(action) => {
                        match action {
                            MessageAction::Disconnect => {
                                let packet = LoginFailPacket::new(LoginFailReason::AccountInUse);
                                client.send_packet(Box::new(packet)).await.unwrap();
                                println!("Connection terminated for {:?}", client.session.addr);
                                connected_accounts.lock().await.remove(&account);
                                client.state = Disconnected;
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
