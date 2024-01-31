use crate::packet::client::FromDecryptedPacket;
use shared::extcrypto::blowfish::Blowfish;
use shared::network::packet::sendable::{SendablePacket, SendablePacketBytes};

pub struct AuthGameGuardPacket {
    session_id: i32,
}

impl AuthGameGuardPacket {
    pub fn new(session_id: i32) -> Self {
        AuthGameGuardPacket { session_id }
    }

    pub fn get_session_id(self) -> i32 {
        self.session_id
    }
}

impl FromDecryptedPacket for AuthGameGuardPacket {
    fn from_decrypted_packet(packet: Vec<u8>) -> AuthGameGuardPacket {
        AuthGameGuardPacket {
            session_id: i32::from_le_bytes(packet.get(1..5).unwrap().try_into().unwrap()),
        }
    }
}

impl SendablePacketBytes for AuthGameGuardPacket {
    fn to_bytes(&self, blowfish: &Blowfish) -> Vec<u8> {
        let mut packet = SendablePacket::new();
        packet.write_uint8(0x07);
        packet.write_int32(self.session_id);
        packet.write_int32(0);
        packet.write_int32(0);
        packet.write_int32(0);
        packet.write_int32(0);
        packet.write_bytes(vec![0u8; 19]);
        packet.blowfish_encrypt(blowfish);

        packet.to_bytes()
    }
}
