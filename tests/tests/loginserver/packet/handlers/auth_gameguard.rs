use loginserver::packet::client::{AuthGameGuardPacket, ClientPacketBytes, FromDecryptedPacket};
use loginserver::packet::handlers::auth_gameguard::handle_gameguard_auth;
use loginserver::packet::server::login_fail::LoginFailPacket;
use loginserver::packet::server::login_fail::LoginFailReason::AccessFailed;
use loginserver::packet::server::GGAuthPacket;
use loginserver::structs::connected_client::ConnectionState::GameGuardAuthorization;
use loginserver::structs::connected_client::{ConnectedClient, LoginClientPackets};
use shared::crypto::blowfish::encrypt_packet;
use shared::extcrypto::blowfish::Blowfish;
use shared::network::packet::prepend_length;
use shared::tokio;
use std::io::ErrorKind::{ConnectionAborted, InvalidData};
use std::net::SocketAddr;
use std::str::FromStr;
use tests::mocks::stream::MockStream;

#[tokio::test]
async fn it_returns_error_on_closed_connection() {
    let mut client = ConnectedClient::new(
        MockStream::new(vec![]),
        SocketAddr::from_str("127.0.0.1:0").unwrap(),
    );
    client.state = GameGuardAuthorization;

    let error = handle_gameguard_auth(&mut client).await.unwrap_err();
    assert_eq!(ConnectionAborted, error.kind());
}

#[tokio::test]
async fn it_returns_error_on_invalid_packet_received() {
    let buffer = [18u16.to_le_bytes().to_vec(), vec![0; 16]].concat();
    let stream = MockStream::new(buffer);
    let mut client = ConnectedClient::new(stream, SocketAddr::from_str("127.0.0.1:0").unwrap());
    client.state = GameGuardAuthorization;

    let error = handle_gameguard_auth(&mut client).await.unwrap_err();
    assert_eq!(InvalidData, error.kind());
    assert_eq!("Did not receive AuthGameGuard packet.", error.to_string());
}

#[tokio::test]
async fn it_returns_error_on_session_id_mismatch() {
    let mut client = ConnectedClient::new(
        MockStream::new(vec![]),
        SocketAddr::from_str("127.0.0.1:0").unwrap(),
    );
    client.state = GameGuardAuthorization;

    let mut packet = AuthGameGuardPacket::new(client.session.session_id - 1)
        .to_bytes(None)
        .unwrap();
    encrypt_packet(&mut packet, &Blowfish::new(&client.session.blowfish_key));
    prepend_length(&mut packet);
    let stream = MockStream::new(packet);
    client.stream = stream;

    let error = handle_gameguard_auth(&mut client).await.unwrap_err();
    assert_eq!(InvalidData, error.kind());
    assert_eq!("Session mismatch detected.", error.to_string());

    let packet = client.read_packet().await.unwrap();
    let packet = LoginFailPacket::from_decrypted_packet(packet, None).unwrap();
    assert_eq!(AccessFailed, packet.get_reason());
}

#[tokio::test]
async fn it_sends_ok_response() {
    let mut client = ConnectedClient::new(
        MockStream::new(vec![]),
        SocketAddr::from_str("127.0.0.1:0").unwrap(),
    );
    client.state = GameGuardAuthorization;
    let mut packet = AuthGameGuardPacket::new(client.session.session_id)
        .to_bytes(None)
        .unwrap();
    encrypt_packet(&mut packet, &Blowfish::new(&client.session.blowfish_key));
    prepend_length(&mut packet);
    let stream = MockStream::new(packet);
    client.stream = stream;

    handle_gameguard_auth(&mut client).await.unwrap();

    let packet = client.read_packet().await.unwrap();
    let packet = GGAuthPacket::from_decrypted_packet(packet, None).unwrap();
    assert_eq!(client.session.session_id, packet.session_id);
}
