use crate::packet::client::FromDecryptedPacket;

pub struct AuthGameGuardPacket {
    session_id: u32,
}

impl AuthGameGuardPacket {
    pub fn get_session_id(self) -> u32 {
        self.session_id
    }
}

impl FromDecryptedPacket for AuthGameGuardPacket {
    fn from_decrypted_packet(packet: Vec<u8>) -> AuthGameGuardPacket {
        AuthGameGuardPacket {
            session_id: u32::from_le_bytes(packet.get(1..5).unwrap().try_into().unwrap()),
        }
    }
}
