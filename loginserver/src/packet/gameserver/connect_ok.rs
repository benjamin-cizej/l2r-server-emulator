use crate::packet::gameserver::{FromDecryptedPacket, ServerPacketBytes};
use shared::network::packet::receivable::ReceivablePacket;
use shared::network::packet::sendable::SendablePacket;

pub struct ConnectOkPacket {}

impl ConnectOkPacket {
    pub fn new() -> Self {
        ConnectOkPacket {}
    }
}

impl FromDecryptedPacket for ConnectOkPacket {
    fn from_decrypted_packet(packet: Vec<u8>) -> std::io::Result<Self> {
        let mut packet = ReceivablePacket::new(packet);
        packet.read_uint8()?;
        Ok(ConnectOkPacket {})
    }
}

impl ServerPacketBytes for ConnectOkPacket {
    fn to_bytes(&self) -> std::io::Result<Vec<u8>> {
        let mut packet = SendablePacket::new();
        packet.write_uint8(0x00);
        Ok(packet.to_vec())
    }
}
