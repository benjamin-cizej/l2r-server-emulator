use client::Client;
use loginserver::login_server;
use loginserver::packet::client::{
    AuthGameGuardPacket, FromDecryptedPacket, RequestAuthLoginPacket,
};
use loginserver::packet::server::login_fail::{LoginFailPacket, LoginFailReason};
use loginserver::packet::server::{GGAuthPacket, LoginOkPacket};
use loginserver::repository::memory::account::InMemoryAccountRepository;
use shared::network::channel::channel_connection::ChannelConnector;
use shared::network::channel::channel_listener::ChannelListener;
use shared::network::channel::channel_stream::ChannelStream;
use shared::network::stream::Streamable;
use shared::tokio;
use shared::tokio::net::{TcpListener, TcpStream};
use shared::tokio::task::AbortHandle;
use std::net::SocketAddr;
use std::str::FromStr;

#[tokio::test]
async fn it_connects_with_tcp() {
    // Start server via TcpListener.
    let client_listener = TcpListener::bind("127.0.0.1:2106").await.unwrap();
    let gameserver_listener = TcpListener::bind("127.0.0.1:6001").await.unwrap();
    let storage = InMemoryAccountRepository::new();
    let handle = tokio::spawn(async move {
        login_server::start_server(client_listener, gameserver_listener, storage)
            .await
            .unwrap();
    });

    // Client connects successfully via TcpStream.
    let mut client = Client::<TcpStream>::connect_tcp("127.0.0.1:2106").await;
    let mut buffer = [0u8; 2];
    let len = client.connection.receive_bytes(&mut buffer).await.unwrap();
    assert_eq!(2, len);

    handle.abort();
}

#[tokio::test]
async fn it_connects_with_channel() {
    // Start server via Mpsc channel.
    let (mut connector, _, handle) = start_channel_server().await;

    // Clients connects successfully via channel.
    let mut client = Client::<ChannelStream>::connect_channel(&mut connector).await;
    let mut buffer = [0u8; 2];
    let len = client.connection.receive_bytes(&mut buffer).await.unwrap();
    assert_eq!(2, len);

    handle.abort();
}

#[tokio::test]
async fn it_sends_init_packet_on_connection() {
    let (mut connector, _, handle) = start_channel_server().await;
    let mut client = Client::<ChannelStream>::connect_channel(&mut connector).await;

    // Read the packet and verify content is correct.
    let packet = client
        .read_init_packet(SocketAddr::from_str("127.0.0.1:0").unwrap())
        .await
        .unwrap();
    assert_eq!(184, client.get_last_bytes_received().len());
    assert_eq!(0x00, client.get_last_bytes_received()[0]);
    assert_eq!(50721, packet.get_protocol());

    handle.abort();
}

#[tokio::test]
async fn it_sends_gg_auth_packet_on_request() {
    let (mut connector, _, handle) = start_channel_server().await;
    let mut client = Client::<ChannelStream>::connect_channel(&mut connector).await;
    client
        .read_init_packet(SocketAddr::from_str("127.0.0.1:0").unwrap())
        .await
        .unwrap();

    // Send the gameguard challenge request.
    let session_id = client.session.clone().unwrap().session_id.clone();
    let packet = Box::new(AuthGameGuardPacket::new(session_id));
    client.send_packet(packet).await.unwrap();

    // Verify the gameguard response content.
    let packet = client.read_packet().await.unwrap();
    let packet = GGAuthPacket::from_decrypted_packet(packet, None).unwrap();
    assert_eq!(session_id, packet.session_id);

    handle.abort();
}

#[tokio::test]
async fn it_disconnects_both_clients_with_same_account() {
    let (mut connector, _, handle) = start_channel_server().await;

    // Connect two clients with the server.
    let mut client1 = Client::<ChannelStream>::connect_channel(&mut connector).await;
    let mut client2 = Client::<ChannelStream>::connect_channel(&mut connector).await;

    // Client 1 logs in successfully.
    login_client(&mut client1, String::from("test"), String::from("test")).await;
    let packet = client1.read_packet().await.unwrap();
    LoginOkPacket::from_decrypted_packet(packet, None).unwrap();

    // Client 2 tries to log in with the same credentials.
    login_client(&mut client2, String::from("test"), String::from("test")).await;
    // Client 2 is rejected - account is already logged in.
    let packet = client2.read_packet().await.unwrap();
    let packet = LoginFailPacket::from_decrypted_packet(packet, None).unwrap();
    assert_eq!(LoginFailReason::AccountInUse, packet.get_reason());

    // Client 1 also disconnects with account in use.
    let packet = client1.read_packet().await.unwrap();
    let packet = LoginFailPacket::from_decrypted_packet(packet, None).unwrap();
    assert_eq!(LoginFailReason::AccountInUse, packet.get_reason());

    // Both connections are terminated.
    client1.read_packet().await.unwrap_err();
    client2.read_packet().await.unwrap_err();

    handle.abort();
}

async fn start_channel_server() -> (ChannelConnector, ChannelConnector, AbortHandle) {
    let client_listener = ChannelListener::new();
    let gameserver_listener = ChannelListener::new();
    let client_connector = client_listener.get_connector();
    let gameserver_connector = gameserver_listener.get_connector();
    let storage = InMemoryAccountRepository::new();
    let handle = tokio::spawn(async move {
        login_server::start_server(client_listener, gameserver_listener, storage)
            .await
            .unwrap();
    });

    (
        client_connector,
        gameserver_connector,
        handle.abort_handle(),
    )
}

async fn login_client<T: Streamable>(client: &mut Client<T>, username: String, password: String) {
    client
        .read_init_packet(SocketAddr::from_str("127.0.0.1:0").unwrap())
        .await
        .unwrap();
    let session_id = client.session.clone().unwrap().session_id.clone();

    let packet = Box::new(AuthGameGuardPacket::new(session_id));
    client.send_packet(packet).await.unwrap();
    client.read_packet().await.unwrap();

    let packet = Box::new(RequestAuthLoginPacket::new(username, password, session_id));
    client.send_packet(packet).await.unwrap();
}
