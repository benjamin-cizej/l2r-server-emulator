use crate::packet::server::ServerPacketBytes;
use shared::network::packet::sendable::SendablePacket;
use shared::structs::session::ServerSession;
use shared::tokio::io;

pub struct PlayOkPacket {
    pub play_ok1: i32,
    pub play_ok2: i32,
}

impl PlayOkPacket {
    pub fn new(play_ok1: i32, play_ok2: i32) -> PlayOkPacket {
        PlayOkPacket { play_ok1, play_ok2 }
    }
}

impl ServerPacketBytes for PlayOkPacket {
    fn to_bytes(&self, _: Option<&ServerSession>) -> io::Result<Vec<u8>> {
        let mut packet = SendablePacket::new();
        packet.write_uint8(0x07);
        packet.write_int32(self.play_ok1);
        packet.write_int32(self.play_ok2);
        packet.pad_bits();
        packet.add_checksum();

        Ok(packet.to_vec())
    }
}
