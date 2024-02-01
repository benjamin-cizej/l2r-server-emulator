use client::Client;
use loginserver::login_server;
use loginserver::packet::client::AuthGameGuardPacket;
use loginserver::packet::server::{GGAuthPacket, InitPacket};
use shared::crypto::blowfish::StaticL2Blowfish;
use shared::extcrypto::blowfish::Blowfish;
use shared::network::channel::channel_connection::ChannelConnector;
use shared::network::channel::channel_listener::ChannelListener;
use shared::network::channel::channel_stream::ChannelStream;
use shared::network::packet::sendable::SendablePacketOutput;
use shared::network::stream::Streamable;
use shared::structs::session::Session;
use shared::tokio;
use shared::tokio::net::{TcpListener, TcpStream};
use shared::tokio::task::AbortHandle;

#[tokio::test]
async fn it_connects_with_tcp() {
    let listener = TcpListener::bind("127.0.0.1:2106").await.unwrap();
    let handle = tokio::spawn(async move {
        login_server::start_server(listener).await.unwrap();
    });

    let mut client = Client::<TcpStream>::connect_tcp("127.0.0.1:2106").await;
    let mut buffer = [0u8; 2];
    let len = client.connection.receive_bytes(&mut buffer).await.unwrap();
    assert_eq!(2, len);

    handle.abort();
}

#[tokio::test]
async fn it_connects_with_channel() {
    let (mut connector, handle) = start_channel_server().await;
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
    let blowfish = Blowfish::new_static();
    let packet: InitPacket = client.read_packet(&blowfish).await;
    let raw_bytes = client.get_last_bytes_received();

    assert_eq!(184, raw_bytes.len());
    assert_eq!(0x00, raw_bytes[0]);
    assert_eq!(50721, packet.get_protocol());

    handle.abort();
}

#[tokio::test]
async fn it_sends_gg_auth_packet_on_request() {
    let (mut connector, handle) = start_channel_server().await;
    let mut client = Client::<ChannelStream>::connect_channel(&mut connector).await;
    let session = Session::new();
    let blowfish = Blowfish::new_static();
    let packet = client.read_packet::<InitPacket>(&blowfish).await;

    let blowfish = Blowfish::new(&packet.get_blowfish_key());
    let session_id = packet.get_session_id();
    let packet: SendablePacketOutput = Box::new(AuthGameGuardPacket::new(session_id));

    client.send_packet(packet, &blowfish, &session).await;

    let packet = client.read_packet::<GGAuthPacket>(&blowfish).await;
    assert_eq!(session_id, packet.session_id);

    handle.abort();
}

async fn start_channel_server() -> (ChannelConnector, AbortHandle) {
    let listener = ChannelListener::new();
    let connector = listener.get_connector();
    let handle = tokio::spawn(async move {
        login_server::start_server(listener).await.unwrap();
    });

    (connector, handle.abort_handle())
}
