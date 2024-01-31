use shared::extcrypto::blowfish::Blowfish;
use shared::network::packet::sendable::{SendablePacket, SendablePacketBytes};

pub enum LoginFailReason {
    AccountInUse,
}

impl LoginFailReason {
    pub fn get_opcode(&self) -> u8 {
        match self {
            LoginFailReason::AccountInUse => 0x07,
        }
    }
}

pub struct LoginFailPacket {
    reason: LoginFailReason,
}

impl LoginFailPacket {
    pub fn new(reason: LoginFailReason) -> Self {
        Self { reason }
    }
}

impl SendablePacketBytes for LoginFailPacket {
    fn to_bytes(&self, blowfish: &Blowfish) -> Vec<u8> {
        let mut packet = SendablePacket::new();
        packet.write_uint8(0x01);
        packet.write_uint8(self.reason.get_opcode());
        packet.pad_bits();
        packet.add_checksum();
        packet.blowfish_encrypt(blowfish);

        packet.to_bytes()
    }
}
