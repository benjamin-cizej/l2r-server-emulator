use loginserver::packet::client::{decrypt_packet, FromDecryptedPacket, RequestAuthLoginPacket};
use shared::extcrypto::blowfish::Blowfish;
use shared::network::packet::sendable::SendablePacketBytes;
use shared::structs::session::Session;

#[test]
fn it_encrypts_and_decrypts() {
    let session = Session::new();
    let blowfish = Blowfish::new(&session.blowfish_key);

    let auth_packet = RequestAuthLoginPacket::new(
        String::from("test_user"),
        String::from("test_password"),
        session.session_id,
    );
    let packet = auth_packet.to_bytes(&blowfish, &session);
    // Skip packet length.
    let (_, packet) = packet.split_at(2);

    let mut decrypted = decrypt_packet(packet.to_vec(), &blowfish);
    RequestAuthLoginPacket::decrypt_credentials(&mut decrypted, &session).unwrap();
    let decrypted_packet = RequestAuthLoginPacket::from_decrypted_packet(decrypted);

    assert_eq!(
        auth_packet.get_session_id(),
        decrypted_packet.get_session_id()
    );
    assert_eq!(auth_packet.get_username(), decrypted_packet.get_username());
    assert_eq!(auth_packet.get_password(), decrypted_packet.get_password());
}
