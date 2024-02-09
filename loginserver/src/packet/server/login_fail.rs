use crate::packet::client::FromDecryptedPacket;
use crate::packet::server::login_fail::LoginFailReason::{
    AccessFailed, AccountInUse, Unknown, UserOrPassWrong,
};
use crate::packet::server::ServerPacketBytes;
use shared::network::packet::receivable::ReceivablePacket;
use shared::network::packet::sendable::SendablePacket;
use shared::structs::session::{ClientSession, ServerSession};
use std::io;

#[derive(Clone, Debug, PartialEq)]
pub enum LoginFailReason {
    AccountInUse,
    AccessFailed,
    Unknown,
    UserOrPassWrong,
}

impl LoginFailReason {
    pub fn get_opcode(&self) -> u8 {
        match self {
            AccountInUse => 0x07,
            AccessFailed => 0x15,
            UserOrPassWrong => 0x02,
            Unknown => 0,
        }
    }

    pub fn from_opcode(opcode: u8) -> Self {
        match opcode {
            0x02 => UserOrPassWrong,
            0x07 => AccountInUse,
            0x15 => AccessFailed,
            _ => Unknown,
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

    pub fn get_reason(&self) -> LoginFailReason {
        self.reason.clone()
    }
}

impl ServerPacketBytes for LoginFailPacket {
    fn to_bytes(&self, _: Option<&ServerSession>) -> io::Result<Vec<u8>> {
        let mut packet = SendablePacket::default();
        packet.write_uint8(0x01);
        packet.write_uint8(self.reason.get_opcode());
        packet.write_bytes(vec![0u8; 6]);
        packet.add_checksum();

        Ok(packet.to_vec())
    }
}

impl FromDecryptedPacket for LoginFailPacket {
    fn from_decrypted_packet(packet: Vec<u8>, _: Option<&ClientSession>) -> io::Result<Self> {
        let mut packet = ReceivablePacket::new(packet);
        packet.read_uint8()?;

        let opcode = packet.read_uint8()?;

        Ok(LoginFailPacket {
            reason: LoginFailReason::from_opcode(opcode),
        })
    }
}
