use crate::packet::gameserver::{FromDecryptedPacket, ServerPacketBytes};
use shared::network::packet::receivable::ReceivablePacket;
use shared::network::packet::sendable::SendablePacket;

#[derive(Debug, PartialEq)]
pub enum ConnectFailReason {
    InvalidKey,
    AlreadyRegistered,
    Unknown,
}

impl ConnectFailReason {
    pub fn get_opcode(&self) -> u8 {
        match self {
            ConnectFailReason::InvalidKey => 0x01,
            ConnectFailReason::AlreadyRegistered => 0x02,
            ConnectFailReason::Unknown => 0x00,
        }
    }

    pub fn from_opcode(opcode: u8) -> Self {
        match opcode {
            0x01 => ConnectFailReason::InvalidKey,
            0x02 => ConnectFailReason::AlreadyRegistered,
            _ => ConnectFailReason::Unknown,
        }
    }
}

pub struct ConnectFailPacket {
    pub reason: ConnectFailReason,
}

impl ConnectFailPacket {
    pub fn new(reason: ConnectFailReason) -> Self {
        ConnectFailPacket { reason }
    }
}

impl FromDecryptedPacket for ConnectFailPacket {
    fn from_decrypted_packet(packet: Vec<u8>) -> std::io::Result<Self> {
        let mut packet = ReceivablePacket::new(packet);
        packet.read_uint8()?;
        let reason = ConnectFailReason::from_opcode(packet.read_uint8()?);
        Ok(ConnectFailPacket { reason })
    }
}

impl ServerPacketBytes for ConnectFailPacket {
    fn to_bytes(&self) -> std::io::Result<Vec<u8>> {
        let mut packet = SendablePacket::default();
        packet.write_uint8(0x01);
        packet.write_uint8(ConnectFailReason::get_opcode(&self.reason));
        Ok(packet.to_vec())
    }
}
