use crate::packet::client::FromDecryptedPacket;
use crate::packet::server::ServerPacketBytes;
use shared::network::packet::receivable::ReceivablePacket;
use shared::network::packet::sendable::SendablePacket;
use shared::structs::session::{ClientSession, ServerSession};
use shared::tokio::io;

pub struct GGAuthPacket {
    pub session_id: i32,
}

impl GGAuthPacket {
    pub fn new(session_id: i32) -> GGAuthPacket {
        GGAuthPacket { session_id }
    }
}

impl ServerPacketBytes for GGAuthPacket {
    fn to_bytes(&self, _: Option<&ServerSession>) -> io::Result<Vec<u8>> {
        let mut packet = SendablePacket::new();
        packet.write_uint8(0x0b);
        packet.write_int32(self.session_id);
        packet.write_int32(0);
        packet.write_int32(0);
        packet.write_int32(0);
        packet.write_int32(0);
        packet.pad_bits();
        packet.add_checksum();

        Ok(packet.to_vec())
    }
}

impl FromDecryptedPacket for GGAuthPacket {
    fn from_decrypted_packet(packet: Vec<u8>, _: Option<&ClientSession>) -> io::Result<Self> {
        let mut packet = ReceivablePacket::new(packet);
        packet.read_uint8()?;
        let session_id = packet.read_int32()?;

        Ok(GGAuthPacket { session_id })
    }
}
