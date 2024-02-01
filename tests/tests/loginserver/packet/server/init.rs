use loginserver::packet::client::{decrypt_packet, FromDecryptedPacket};
use loginserver::packet::server::InitPacket;
use shared::crypto::blowfish::StaticL2Blowfish;
use shared::extcrypto::blowfish::Blowfish;
use shared::network::packet::sendable::SendablePacketBytes;
use shared::structs::session::Session;

#[test]
fn it_encrypts_and_decrypts_packet() {
    let session = Session::new();
    let blowfish = Blowfish::new_static();
    let init_packet = InitPacket::new(&session);

    let packet = init_packet.to_bytes(&blowfish, &session);
    // Skip packet length.
    let (_, packet) = packet.split_at(2);

    let decrypted = decrypt_packet(packet.to_vec(), &blowfish);
    let decrypted_init = InitPacket::from_decrypted_packet(decrypted);

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
