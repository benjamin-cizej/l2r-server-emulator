use loginserver::packet::client::FromDecryptedPacket;
use loginserver::packet::server::{InitPacket, ServerPacketBytes};
use shared::crypto::blowfish::{decrypt_packet, encrypt_packet, StaticL2Blowfish};
use shared::extcrypto::blowfish::Blowfish;
use shared::structs::session::ServerSession;
use std::net::SocketAddr;
use std::str::FromStr;

#[test]
fn it_encrypts_and_decrypts_packet() {
    let session = ServerSession::new(SocketAddr::from_str("127.0.0.1:0").unwrap());
    let blowfish = Blowfish::new_static();
    let init_packet = InitPacket::new(&session);

    let mut packet = init_packet.to_bytes(None).unwrap();
    encrypt_packet(&mut packet, &blowfish);
    decrypt_packet(&mut packet, &blowfish);
    let decrypted_init = InitPacket::from_decrypted_packet(packet, None).unwrap();

    assert_eq!(
        init_packet.get_session_id(),
        decrypted_init.get_session_id()
    );
    assert_eq!(init_packet.get_protocol(), decrypted_init.get_protocol());
    assert_eq!(
        init_packet.get_blowfish_key(),
        decrypted_init.get_blowfish_key()
    );
    assert_eq!(
        init_packet.get_modulus().to_value(),
        decrypted_init.get_modulus().to_value()
    );
}
