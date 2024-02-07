use client::Client;
use loginserver::login_server;
use loginserver::packet::client::{
    AuthGameGuardPacket, ClientPacketBytes, FromDecryptedPacket, RequestAuthLoginPacket,
};
use loginserver::packet::server::login_fail::{LoginFailPacket, LoginFailReason};
use loginserver::packet::server::{GGAuthPacket, InitPacket, LoginOkPacket};
use loginserver::repository::memory::account::MemoryAccountRepository;
use shared::crypto::blowfish::{decrypt_packet, encrypt_packet, StaticL2Blowfish};
use shared::extcrypto::blowfish::Blowfish;
use shared::network::channel::channel_connection::ChannelConnector;
use shared::network::channel::channel_listener::ChannelListener;
use shared::network::channel::channel_stream::ChannelStream;
use shared::network::stream::Streamable;
use shared::structs::session::ClientSession;
use shared::tokio;
use shared::tokio::net::{TcpListener, TcpStream};
use shared::tokio::task::AbortHandle;
use std::net::SocketAddr;
use std::str::FromStr;

#[tokio::test]
async fn it_connects_with_tcp() {
    // Start server via TcpListener.
    let listener = TcpListener::bind("127.0.0.1:2106").await.unwrap();
    let storage = MemoryAccountRepository::new();
    let handle = tokio::spawn(async move {
        login_server::start_server(listener, storage).await.unwrap();
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
    let (mut connector, handle) = start_channel_server().await;

    // Clients connects successfully via channel.
    let mut client = Client::<ChannelStream>::connect_channel(&mut connector).await;
    let mut buffer = [0u8; 2];
    let len = client.connection.receive_bytes(&mut buffer).await.unwrap();
    assert_eq!(2, len);

    handle.abort();
}

#[tokio::test]
async fn it_sends_init_packet_on_connection() {
    let (mut connector, handle) = start_channel_server().await;
    let mut client = Client::<ChannelStream>::connect_channel(&mut connector).await;

    // Read the init packet after connection is established.
    let blowfish = Blowfish::new_static();

    // Decrypt the packet and verify content is correct.
    let mut packet = client.read_packet().await.unwrap();
    decrypt_packet(&mut packet, &blowfish);
    assert_eq!(184, packet.len());
    assert_eq!(0x00, packet[0]);

    let packet = InitPacket::from_decrypted_packet(packet, None).unwrap();
    assert_eq!(50721, packet.get_protocol());

    handle.abort();
}

#[tokio::test]
async fn it_sends_gg_auth_packet_on_request() {
    let (mut connector, handle) = start_channel_server().await;
    let mut client = Client::<ChannelStream>::connect_channel(&mut connector).await;

    // Read the init packet after connection is established.
    let mut packet = client.read_packet().await.unwrap();

    // Decrypt the packet and start the client session.
    decrypt_packet(&mut packet, &Blowfish::new_static());
    let packet = InitPacket::from_decrypted_packet(packet, None).unwrap();
    let blowfish = Blowfish::new(&packet.get_blowfish_key());
    let session = packet.to_client_session(SocketAddr::from_str("127.0.0.1:0").unwrap());

    // Send the gameguard challenge request.
    let session_id = session.session_id;
    let mut packet = AuthGameGuardPacket::new(session.session_id.clone())
        .to_bytes(Some(&session))
        .unwrap();
    encrypt_packet(&mut packet, &blowfish);
    client.send_packet(packet).await.unwrap();

    // Verify the gameguard response content.
    let mut packet = client.read_packet().await.unwrap();
    decrypt_packet(&mut packet, &Blowfish::new(&session.blowfish_key));
    let packet = GGAuthPacket::from_decrypted_packet(packet, None).unwrap();

    assert_eq!(session_id, packet.session_id);

    handle.abort();
}

#[tokio::test]
async fn it_disconnects_both_clients_with_same_account() {
    let (mut connector, handle) = start_channel_server().await;

    // Connect two clients with the server.
    let mut client1 = Client::<ChannelStream>::connect_channel(&mut connector).await;
    let mut client2 = Client::<ChannelStream>::connect_channel(&mut connector).await;

    // Client 1 logs in successfully.
    let session1 = login_client(&mut client1, String::from("test"), String::from("test")).await;
    let mut packet = client1.read_packet().await.unwrap();
    decrypt_packet(&mut packet, &Blowfish::new(&session1.blowfish_key));
    let packet = LoginOkPacket::from_decrypted_packet(packet, None).unwrap();
    assert_eq!(0, packet.login_ok1);
    assert_eq!(0, packet.login_ok2);

    // Client 2 tries to log in with the same credentials.
    let session2 = login_client(&mut client2, String::from("test"), String::from("test")).await;
    // Client 2 is rejected - account is already logged in.
    let mut packet = client2.read_packet().await.unwrap();
    decrypt_packet(&mut packet, &Blowfish::new(&session2.blowfish_key));
    let packet = LoginFailPacket::from_decrypted_packet(packet, None).unwrap();
    assert_eq!(LoginFailReason::AccountInUse, packet.get_reason());

    // Client 1 also receives account in use packet.
    let mut packet = client1.read_packet().await.unwrap();
    decrypt_packet(&mut packet, &Blowfish::new(&session1.blowfish_key));
    let packet = LoginFailPacket::from_decrypted_packet(packet, None).unwrap();
    assert_eq!(LoginFailReason::AccountInUse, packet.get_reason());

    // Both connections are terminated.
    client1.read_packet().await.unwrap_err();
    client2.read_packet().await.unwrap_err();

    handle.abort();
}

async fn start_channel_server() -> (ChannelConnector, AbortHandle) {
    let listener = ChannelListener::new();
    let connector = listener.get_connector();
    let storage = MemoryAccountRepository::new();
    let handle = tokio::spawn(async move {
        login_server::start_server(listener, storage).await.unwrap();
    });

    (connector, handle.abort_handle())
}

async fn login_client<T: Streamable>(
    client: &mut Client<T>,
    username: String,
    password: String,
) -> ClientSession {
    let addr = SocketAddr::from_str("127.0.0.1:0").unwrap();
    let blowfish = Blowfish::new_static();

    let mut packet = client.read_packet().await.unwrap();
    decrypt_packet(&mut packet, &blowfish);

    let packet = InitPacket::from_decrypted_packet(packet, None).unwrap();
    let session = packet.to_client_session(addr);

    let mut packet = AuthGameGuardPacket::new(session.session_id)
        .to_bytes(Some(&session))
        .unwrap();

    encrypt_packet(&mut packet, &Blowfish::new(&session.blowfish_key));
    client.send_packet(packet).await.unwrap();
    client.read_packet().await.unwrap();

    let mut packet = RequestAuthLoginPacket::new(username, password, session.session_id)
        .to_bytes(Some(&session))
        .unwrap();
    encrypt_packet(&mut packet, &Blowfish::new(&session.blowfish_key));
    client.send_packet(packet).await.unwrap();

    session
}
