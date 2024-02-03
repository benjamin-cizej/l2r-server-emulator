use loginserver::packet::client::{AuthGameGuardPacket, ClientPacketBytes, FromDecryptedPacket};
use loginserver::packet::handlers::auth_gameguard::handle_gameguard_auth;
use loginserver::packet::server::login_fail::LoginFailPacket;
use loginserver::packet::server::login_fail::LoginFailReason::AccessFailed;
use loginserver::packet::server::GGAuthPacket;
use shared::crypto::blowfish::{decrypt_packet, encrypt_packet};
use shared::extcrypto::blowfish::Blowfish;
use shared::network::packet::prepend_length;
use shared::network::read_packet;
use shared::structs::session::ServerSession;
use shared::tokio;
use std::net::SocketAddr;
use std::str::FromStr;
use tests::mocks::stream::MockStream;

#[tokio::test]
async fn it_returns_error_on_closed_connection() {
    let mut stream = MockStream::new(vec![]);
    let session = ServerSession::new(SocketAddr::from_str("127.0.0.1:0").unwrap());

    handle_gameguard_auth(&mut stream, &session)
        .await
        .unwrap_err();
}

#[tokio::test]
async fn it_returns_error_on_invalid_packet_received() {
    let buffer = [18u16.to_le_bytes().to_vec(), vec![0; 16]].concat();
    let mut stream = MockStream::new(buffer);
    let session = ServerSession::new(SocketAddr::from_str("127.0.0.1:0").unwrap());

    handle_gameguard_auth(&mut stream, &session)
        .await
        .unwrap_err();
}

#[tokio::test]
async fn it_returns_error_on_session_id_mismatch() {
    let session = ServerSession::new(SocketAddr::from_str("127.0.0.1:0").unwrap());
    let mut packet = AuthGameGuardPacket::new(session.session_id - 1)
        .to_bytes(None)
        .unwrap();
    encrypt_packet(&mut packet, &Blowfish::new(&session.blowfish_key));
    prepend_length(&mut packet);

    let mut stream = MockStream::new(packet);
    handle_gameguard_auth(&mut stream, &session)
        .await
        .unwrap_err();

    let mut packet = read_packet(&mut stream).await.unwrap();
    decrypt_packet(&mut packet, &Blowfish::new(&session.blowfish_key));
    let packet = LoginFailPacket::from_decrypted_packet(packet, None).unwrap();
    assert_eq!(AccessFailed, packet.get_reason());
}

#[tokio::test]
async fn it_sends_ok_response() {
    let session = ServerSession::new(SocketAddr::from_str("127.0.0.1:0").unwrap());
    let mut packet = AuthGameGuardPacket::new(session.session_id)
        .to_bytes(None)
        .unwrap();
    encrypt_packet(&mut packet, &Blowfish::new(&session.blowfish_key));
    prepend_length(&mut packet);

    let mut stream = MockStream::new(packet);
    handle_gameguard_auth(&mut stream, &session).await.unwrap();

    let mut packet = read_packet(&mut stream).await.unwrap();
    decrypt_packet(&mut packet, &Blowfish::new(&session.blowfish_key));
    let packet = GGAuthPacket::from_decrypted_packet(packet, None).unwrap();
    assert_eq!(session.session_id, packet.session_id);
}
