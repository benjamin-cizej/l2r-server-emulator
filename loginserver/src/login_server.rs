use crate::packet::gameserver;
use crate::packet::gameserver::FromDecryptedPacket;
use crate::packet::handlers::auth_gameguard::handle_gameguard_auth;
use crate::packet::handlers::login_credentials::handle_login_credentials;
use crate::packet::server::login_fail::{LoginFailPacket, LoginFailReason};
use crate::packet::server::{handle_packet, InitPacket, ServerPacketBytes};
use crate::repository::account::AccountRepository;
use crate::structs::connected_client::ConnectionState::Disconnected;
use crate::structs::connected_client::{ConnectedClient, LoginClientPackets};
use shared::crypto::blowfish::{decrypt_packet, encrypt_packet, StaticL2Blowfish};
use shared::extcrypto::blowfish::Blowfish;
use shared::network::listener::Acceptable;
use shared::network::stream::Streamable;
use shared::network::{read_packet, send_packet};
use shared::tokio;
use shared::tokio::select;
use shared::tokio::sync::broadcast::Sender;
use shared::tokio::sync::{broadcast, Mutex};
use std::collections::HashMap;
use std::io::{
    ErrorKind::{AlreadyExists, ConnectionAborted, Unsupported},
    Result,
};
use std::sync::Arc;

#[derive(Clone, Debug)]
pub enum MessageAction {
    Disconnect,
}

pub type ConnectedAccounts = Arc<Mutex<HashMap<String, Sender<MessageAction>>>>;
pub type ConnectedGameServers = Arc<Mutex<HashMap<u8, String>>>;

pub async fn start_server(
    mut client_listener: impl Acceptable,
    mut gameserver_listener: impl Acceptable,
    repository: impl AccountRepository,
) -> Result<()> {
    let connected_accounts: ConnectedAccounts = Arc::new(Mutex::new(HashMap::new()));
    let connected_gameservers: ConnectedGameServers = Arc::new(Mutex::new(HashMap::new()));
    let repository = Arc::new(Mutex::new(repository));

    loop {
        select! {
            _ = handle_client_connections(&mut client_listener, &connected_accounts, &repository) => {},
            _ = handle_gameserver_connections(&mut gameserver_listener, connected_gameservers.clone()) => {}
        }
    }
}

async fn handle_gameserver_connections(
    listener: &mut impl Acceptable,
    gameservers: ConnectedGameServers,
) {
    let (mut stream, addr) = match listener.accept_connection().await {
        Err(e) => {
            println!("Connection could not be established: {:?}", e);
            return;
        }
        Ok((stream, addr)) => (stream, addr),
    };
    println!("New gameserver connection from {:?}", addr);

    let blowfish = Blowfish::new_static();
    let mut packet = read_packet(&mut stream).await.unwrap();
    decrypt_packet(&mut packet, &blowfish);
    let packet = gameserver::InitPacket::from_decrypted_packet(packet).unwrap();
    if packet.auth_key != "test_auth_key".to_string() {
        println!("Invalid auth key. Disconnecting...");
        return;
    }

    {
        let id = packet.id.clone();
        let mut lock = gameservers.lock().await;
        match lock.get(&id) {
            None => {
                let name = packet.name.clone();
                lock.insert(id, name);
            }
            Some(_) => {
                println!(
                    "Gameserver with the id {} is already registered. Disconnecting...",
                    id
                );
                return;
            }
        };
    }
}

async fn handle_client_connections(
    listener: &mut impl Acceptable,
    connected_accounts: &ConnectedAccounts,
    repository: &Arc<Mutex<impl AccountRepository + Sized>>,
) {
    let (stream, addr) = match listener.accept_connection().await {
        Err(e) => {
            println!("Connection could not be established: {:?}", e);
            return;
        }
        Ok((stream, addr)) => (stream, addr),
    };
    let client = ConnectedClient::new(stream, addr);
    println!("Connection established from {:?}", addr);

    let (tx, _) = broadcast::channel::<MessageAction>(10);
    let cloned_list = connected_accounts.clone();
    let cloned_repo = repository.clone();
    tokio::spawn(async move { handle_client_stream(client, tx, cloned_list, cloned_repo).await });
}

async fn handle_client_stream(
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
                        Unsupported => {
                            println!("Unknown packet received: {}", e.to_string());
                            continue;
                        }
                        ConnectionAborted => {
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
                                let packet = Box::new(LoginFailPacket::new(LoginFailReason::AccountInUse));
                                client.send_packet(packet).await.unwrap();
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
