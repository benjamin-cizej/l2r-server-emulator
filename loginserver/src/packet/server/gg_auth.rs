use crate::packet::client::FromDecryptedPacket;
use shared::extcrypto::blowfish::Blowfish;
use shared::network::packet::receivable::ReceivablePacket;
use shared::network::packet::sendable::{SendablePacket, SendablePacketBytes};
use shared::structs::session::Session;

pub struct GGAuthPacket {
    pub session_id: i32,
}

impl GGAuthPacket {
    pub fn new(session_id: i32) -> GGAuthPacket {
        GGAuthPacket { session_id }
    }
}

impl SendablePacketBytes for GGAuthPacket {
    fn to_bytes(&self, blowfish: &Blowfish, session: &Session) -> Vec<u8> {
        let mut packet = SendablePacket::new();
        packet.write_uint8(0x0b);
        packet.write_int32(session.session_id);
        packet.write_int32(0);
        packet.write_int32(0);
        packet.write_int32(0);
        packet.write_int32(0);
        packet.pad_bits();
        packet.add_checksum();
        packet.blowfish_encrypt(blowfish);

        packet.to_bytes()
    }
}

impl FromDecryptedPacket for GGAuthPacket {
    fn from_decrypted_packet(packet: Vec<u8>) -> Self {
        let mut packet = ReceivablePacket::new(packet);
        packet.read_uint8().unwrap();
        let session_id = packet.read_int32().unwrap();

        GGAuthPacket { session_id }
    }
}
