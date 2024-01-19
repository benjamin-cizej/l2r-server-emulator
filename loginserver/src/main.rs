use std::collections::HashMap;
use std::error::Error;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::sync::Arc;

use shared::extcrypto::blowfish::Blowfish;
use shared::network::send_packet;
use shared::structs::session::Session;
use shared::tokio;
use shared::tokio::net::{TcpListener, TcpStream};
use shared::tokio::select;
use shared::tokio::sync::broadcast::Sender;
use shared::tokio::sync::{broadcast, Mutex};

use crate::login_flow::{handle_gameguard_auth, handle_login_credentials};
use crate::packet::client::handle_packet;
use crate::packet::server::login_fail::{LoginFailPacket, LoginFailReason};
use crate::packet::server::InitPacket;

mod login_flow;
mod packet;

#[derive(Clone, Debug)]
enum MessageAction {
    Disconnect,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let login_server = TcpListener::bind("127.0.0.1:2106").await?;
    let clients = Arc::new(Mutex::new(HashMap::<
        String,
        Sender<(MessageAction, Vec<u8>)>,
    >::new()));

    loop {
        let (stream, addr) = match login_server.accept().await {
            Err(e) => {
                println!("Connection could not be established: {:?}", e);
                continue;
            }
            Ok((stream, addr)) => (stream, addr),
        };

        let (client_tx, _) = broadcast::channel::<(MessageAction, Vec<u8>)>(10);

        println!("Connection established from {:?}", addr);
        stream.set_nodelay(true).unwrap();
        let cloned_clients = clients.clone();
        tokio::spawn(async move {
            handle_stream(stream, addr, client_tx.clone(), cloned_clients).await
        });
    }
}

async fn handle_stream(
    mut stream: TcpStream,
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
            ErrorKind::AlreadyExists => {
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
