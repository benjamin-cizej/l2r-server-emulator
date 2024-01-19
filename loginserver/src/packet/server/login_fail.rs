use shared::extcrypto::blowfish::Blowfish;
use shared::network::serverpacket::{ServerPacket, ServerPacketOutputtable};

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
    blowfish: Blowfish,
}

impl LoginFailPacket {
    pub fn new(reason: LoginFailReason, blowfish: &Blowfish) -> Self {
        Self {
            reason,
            blowfish: blowfish.clone(),
        }
    }
}

impl ServerPacketOutputtable for LoginFailPacket {
    fn to_output_stream(&self) -> Vec<u8> {
        let mut packet = ServerPacket::new();
        packet.write_uint8(0x01);
        packet.write_uint8(self.reason.get_opcode());
        packet.pad_bits();
        packet.add_checksum();
        packet.blowfish_encrypt(self.blowfish);

        packet.prep_output()
    }
}
