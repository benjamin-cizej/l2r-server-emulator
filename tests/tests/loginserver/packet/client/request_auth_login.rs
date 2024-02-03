use loginserver::packet::client::{ClientPacketBytes, RequestAuthLoginPacket};
use loginserver::packet::server::FromDecryptedPacket;
use shared::crypto::blowfish::{decrypt_packet, encrypt_packet};
use shared::extcrypto::blowfish::Blowfish;
use shared::structs::session::ServerSession;
use std::net::SocketAddr;
use std::str::FromStr;

#[test]
fn it_encrypts_and_decrypts() {
    let server_session = ServerSession::new(SocketAddr::from_str("127.0.0.1:0").unwrap());
    let client_session = server_session.clone().to_client_session();

    let auth_packet = RequestAuthLoginPacket::new(
        String::from("test_user"),
        String::from("test_password"),
        client_session.session_id,
    );

    let mut packet = auth_packet.to_bytes(Some(&client_session)).unwrap();
    encrypt_packet(&mut packet, &Blowfish::new(&client_session.blowfish_key));
    decrypt_packet(&mut packet, &Blowfish::new(&server_session.blowfish_key));
    let decrypted_packet =
        RequestAuthLoginPacket::from_decrypted_packet(packet, Some(&server_session)).unwrap();

    assert_eq!(
        auth_packet.get_session_id(),
        decrypted_packet.get_session_id()
    );
    assert_eq!(auth_packet.get_username(), decrypted_packet.get_username());
    assert_eq!(auth_packet.get_password(), decrypted_packet.get_password());
}
