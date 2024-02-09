use crate::login_server::ConnectedGameServers;
use crate::packet::gameserver::{
    ConnectFailPacket, ConnectFailReason, ConnectOkPacket, FromDecryptedPacket, InitPacket,
};
use crate::structs::connected_gameserver::{ConnectedGameServer, GameserverClientPacket};
use shared::network::listener::Acceptable;
use shared::network::stream::Streamable;
use shared::tokio;
use shared::tokio::io;
use std::io::ErrorKind;

pub async fn handle_gameserver_connections(
    listener: &mut impl Acceptable,
    gameservers: &ConnectedGameServers,
) {
    loop {
        let (stream, addr) = match listener.accept_connection().await {
            Err(e) => {
                println!("Connection with gameserver could not be established: {}", e);
                return;
            }
            Ok((stream, addr)) => (stream, addr),
        };
        println!("New gameserver connection from {:?}", addr);

        let client = ConnectedGameServer::new(stream);
        let gameservers_clone = gameservers.clone();
        tokio::spawn(async move { handle_connection(client, gameservers_clone).await });
    }
}

async fn handle_connection(
    mut client: ConnectedGameServer<impl Streamable>,
    gameservers: ConnectedGameServers,
) {
    let gameserver_id = match validate_connection(&mut client, &gameservers).await {
        Ok(id) => {
            let packet = ConnectOkPacket::default();
            client.send_packet(Box::new(packet)).await.unwrap();
            id
        }
        Err(e) => {
            println!("Error validating connection: {}", e);
            return;
        }
    };

    loop {
        match client.read_packet().await {
            Ok(_) => {}
            Err(e) => {
                println!(
                    "Connection with gameserver id {} closed: {}",
                    gameserver_id, e
                );
                gameservers.lock().await.remove(&gameserver_id);
                return;
            }
        }
    }
}

async fn validate_connection(
    client: &mut ConnectedGameServer<impl Streamable>,
    gameservers: &ConnectedGameServers,
) -> io::Result<u8> {
    let packet = match client.read_packet().await {
        Ok(packet) => packet,
        Err(_) => {
            return Err(io::Error::new(
                ErrorKind::NotFound,
                "Failed to receive initial packet",
            ));
        }
    };
    if packet[0] != 0x00 {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            format!("Invalid packet received: 0x{:02X?}", packet[0]),
        ));
    }

    let packet = InitPacket::from_decrypted_packet(packet)?;
    if packet.auth_key != "test_auth_key" {
        let packet = ConnectFailPacket::new(ConnectFailReason::InvalidKey);
        client.send_packet(Box::new(packet)).await?;
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            "Invalid auth key",
        ));
    }

    let id = packet.id;
    {
        let mut lock = gameservers.lock().await;
        match lock.get(&id) {
            None => {
                let name = packet.name.clone();
                lock.insert(id, name);
            }
            Some(_) => {
                let packet = ConnectFailPacket::new(ConnectFailReason::AlreadyRegistered);
                client.send_packet(Box::new(packet)).await?;
                return Err(io::Error::new(
                    ErrorKind::AlreadyExists,
                    "Gameserver with this id is already registered",
                ));
            }
        };
    }

    Ok(id)
}
