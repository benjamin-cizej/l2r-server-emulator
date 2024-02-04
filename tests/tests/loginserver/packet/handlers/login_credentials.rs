use loginserver::login_server::{AccountsList, MessageAction};
use loginserver::packet::client::{ClientPacketBytes, FromDecryptedPacket, RequestAuthLoginPacket};
use loginserver::packet::handlers::login_credentials::handle_login_credentials;
use loginserver::packet::server::login_fail::LoginFailPacket;
use loginserver::packet::server::login_fail::LoginFailReason::AccessFailed;
use shared::crypto::blowfish::{decrypt_packet, encrypt_packet};
use shared::extcrypto::blowfish::Blowfish;
use shared::network::packet::prepend_length;
use shared::network::read_packet;
use shared::structs::session::ServerSession;
use shared::tokio;
use shared::tokio::sync::broadcast::Sender;
use shared::tokio::sync::Mutex;
use std::collections::HashMap;
use std::io::ErrorKind::{ConnectionAborted, InvalidData};
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use tests::mocks::stream::MockStream;

#[tokio::test]
async fn it_returns_error_on_closed_connection() {
    let mut stream = MockStream::new(vec![]);
    let session = ServerSession::new(SocketAddr::from_str("127.0.0.1:0").unwrap());
    let clients: AccountsList = Arc::new(Mutex::new(HashMap::<
        String,
        Sender<(MessageAction, Vec<u8>)>,
    >::new()));

    let error = handle_login_credentials(&mut stream, &session, &clients)
        .await
        .unwrap_err();
    assert_eq!(ConnectionAborted, error.kind());
}

#[tokio::test]
async fn it_returns_error_on_invalid_packet_received() {
    let mut buffer = vec![0; 16];
    prepend_length(&mut buffer);
    let mut stream = MockStream::new(buffer);
    let session = ServerSession::new(SocketAddr::from_str("127.0.0.1:0").unwrap());
    let clients: AccountsList = Arc::new(Mutex::new(HashMap::<
        String,
        Sender<(MessageAction, Vec<u8>)>,
    >::new()));

    let error = handle_login_credentials(&mut stream, &session, &clients)
        .await
        .unwrap_err();
    assert_eq!(InvalidData, error.kind());
    assert_eq!(
        "Did not receive RequestAuthLogin packet.",
        error.to_string()
    );
}

#[tokio::test]
async fn it_returns_error_on_session_id_mismatch() {
    let clients: AccountsList = Arc::new(Mutex::new(HashMap::<
        String,
        Sender<(MessageAction, Vec<u8>)>,
    >::new()));
    let server_session = ServerSession::new(SocketAddr::from_str("127.0.0.1:0").unwrap());
    let client_session = server_session.clone().to_client_session();
    let mut packet = RequestAuthLoginPacket::new(
        String::from("test"),
        String::from("test"),
        client_session.session_id - 1,
    )
    .to_bytes(Some(&client_session))
    .unwrap();
    encrypt_packet(&mut packet, &Blowfish::new(&client_session.blowfish_key));
    prepend_length(&mut packet);

    let mut stream = MockStream::new(packet);
    let error = handle_login_credentials(&mut stream, &server_session, &clients)
        .await
        .unwrap_err();
    assert_eq!(InvalidData, error.kind());
    assert_eq!("Session mismatch detected.", error.to_string());

    let mut packet = read_packet(&mut stream).await.unwrap();
    decrypt_packet(&mut packet, &Blowfish::new(&server_session.blowfish_key));
    let packet = LoginFailPacket::from_decrypted_packet(packet, None).unwrap();
    assert_eq!(AccessFailed, packet.get_reason());
}
