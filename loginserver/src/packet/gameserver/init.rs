use crate::packet::gameserver::{FromDecryptedPacket, ServerPacketBytes};
use shared::network::packet::receivable::ReceivablePacket;
use shared::network::packet::sendable::SendablePacket;
use std::io::Result;

#[derive(Debug)]
pub struct InitPacket {
    pub auth_key: String,
    pub id: u8,
    pub name: String,
}

impl InitPacket {
    pub fn new(auth_key: String, id: u8, name: String) -> Self {
        InitPacket { auth_key, id, name }
    }
}

impl FromDecryptedPacket for InitPacket {
    fn from_decrypted_packet(packet: Vec<u8>) -> Result<Self> {
        let mut packet = ReceivablePacket::new(packet);
        packet.read_uint8()?;
        let auth_key = packet.read_text(None)?;
        let id = packet.read_uint8()?;
        let name = packet.read_text(None)?;

        Ok(InitPacket { auth_key, id, name })
    }
}

impl ServerPacketBytes for InitPacket {
    fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut packet = SendablePacket::default();
        packet.write_uint8(0x00);
        packet.write_text(&self.auth_key);
        packet.write_uint8(self.id);
        packet.write_text(&self.name);

        Ok(packet.to_vec())
    }
}
