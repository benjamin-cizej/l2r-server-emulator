use crate::packet::server::ServerPacketBytes;
use shared::network::packet::sendable::SendablePacket;
use shared::structs::session::ServerSession;
use std::io;

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

impl ServerPacketBytes for LoginFailPacket {
    fn to_bytes(&self, _: Option<&ServerSession>) -> io::Result<Vec<u8>> {
        let mut packet = SendablePacket::new();
        packet.write_uint8(0x01);
        packet.write_uint8(self.reason.get_opcode());
        packet.write_bytes(vec![0u8, 2]);
        packet.add_checksum();

        Ok(packet.to_vec())
    }
}
