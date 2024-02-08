use std::io::Result;
use shared::network::packet::receivable::ReceivablePacket;
use shared::num::ToPrimitive;
use crate::packet::gameserver::FromDecryptedPacket;

pub struct InitPacket {
    pub auth_key: String,
    pub id: u8,
    pub name: String,
}

impl FromDecryptedPacket for InitPacket {
    fn from_decrypted_packet(packet: Vec<u8>) -> Result<Self> {
        let mut packet = ReceivablePacket::new(packet);
        packet.read_uint8()?;
        let len = packet.read_uint16()?.to_usize().unwrap();
        let auth_key = packet.read_text(len)?;
        let id = packet.read_uint8()?;
        let len = packet.read_uint16()?.to_usize().unwrap();
        let name = packet.read_text(len)?;

        Ok(InitPacket {
            auth_key,
            id,
            name
        })
    }
}