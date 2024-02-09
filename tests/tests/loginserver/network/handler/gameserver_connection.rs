use loginserver::login_server::ConnectedGameServers;
use loginserver::network::handler::gameserver_connection::handle_gameserver_connections;
use loginserver::packet::gameserver::{
    ConnectFailPacket, ConnectFailReason, ConnectOkPacket, FromDecryptedPacket, InitPacket,
};
use loginserver::structs::connected_gameserver::{ConnectedGameServer, GameserverClientPacket};
use shared::crypto::blowfish::{encrypt_packet, StaticL2Blowfish};
use shared::extcrypto::blowfish::Blowfish;
use shared::network::channel::channel_connection::{connect, ChannelConnector};
use shared::network::channel::channel_listener::ChannelListener;
use shared::network::stream::Streamable;
use shared::network::{read_packet, send_packet};
use shared::tokio;
use shared::tokio::sync::Mutex;
use shared::tokio::task::AbortHandle;
use std::collections::HashMap;
use std::sync::Arc;

#[tokio::test]
async fn it_fails_to_connect_with_closed_connection() {
    let (mut connector, handle) = start_handler().await;
    let mut stream = connect(&mut connector).await.unwrap();
    stream.send_bytes(&[]).await.unwrap();
    read_packet(&mut stream).await.unwrap_err();
    handle.abort();
}

#[tokio::test]
async fn it_fails_to_connect_with_invalid_packet() {
    let (mut connector, handle) = start_handler().await;
    let mut stream = connect(&mut connector).await.unwrap();

    let mut packet = vec![1; 16];
    encrypt_packet(&mut packet, &Blowfish::new_static());
    send_packet(&mut stream, packet).await.unwrap();
    read_packet(&mut stream).await.unwrap_err();
    handle.abort();
}

#[tokio::test]
async fn it_fails_to_connect_with_invalid_auth_key() {
    let (mut connector, handle) = start_handler().await;
    let stream = connect(&mut connector).await.unwrap();
    let mut client = ConnectedGameServer::new(stream);

    let packet = InitPacket::new("abc".to_string(), 1, "Bartz".to_string());
    client.send_packet(Box::new(packet)).await.unwrap();
    let packet = client.read_packet().await.unwrap();
    let packet = ConnectFailPacket::from_decrypted_packet(packet).unwrap();
    assert_eq!(ConnectFailReason::InvalidKey, packet.reason);
    client.read_packet().await.unwrap_err();
    handle.abort();
}

#[tokio::test]
async fn it_fails_to_connect_when_gameserver_id_registered() {
    let (mut connector, handle) = start_handler().await;

    let stream = connect(&mut connector).await.unwrap();
    let mut client = ConnectedGameServer::new(stream);
    let packet = InitPacket::new("test_auth_key".to_string(), 1, "Bartz".to_string());
    client.send_packet(Box::new(packet)).await.unwrap();
    let packet = client.read_packet().await.unwrap();
    ConnectOkPacket::from_decrypted_packet(packet).unwrap();

    let stream = connect(&mut connector).await.unwrap();
    let mut client = ConnectedGameServer::new(stream);
    let packet = InitPacket::new("test_auth_key".to_string(), 1, "Bartz".to_string());
    client.send_packet(Box::new(packet)).await.unwrap();
    let packet = client.read_packet().await.unwrap();
    let packet = ConnectFailPacket::from_decrypted_packet(packet).unwrap();
    assert_eq!(ConnectFailReason::AlreadyRegistered, packet.reason);
    client.read_packet().await.unwrap_err();

    handle.abort();
}

async fn start_handler() -> (ChannelConnector, AbortHandle) {
    let mut listener = ChannelListener::new();
    let connector = listener.get_connector();
    let gameservers: ConnectedGameServers = Arc::new(Mutex::new(HashMap::new()));

    let handle =
        tokio::spawn(
            async move { handle_gameserver_connections(&mut listener, &gameservers).await },
        );
    (connector, handle.abort_handle())
}
