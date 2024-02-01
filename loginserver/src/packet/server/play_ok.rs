use shared::extcrypto::blowfish::Blowfish;
use shared::network::packet::sendable::{SendablePacket, SendablePacketBytes};
use shared::structs::session::Session;

pub struct PlayOkPacket {
    pub play_ok1: i32,
    pub play_ok2: i32,
}

impl PlayOkPacket {
    pub fn new(play_ok1: i32, play_ok2: i32) -> PlayOkPacket {
        PlayOkPacket { play_ok1, play_ok2 }
    }
}

impl SendablePacketBytes for PlayOkPacket {
    fn to_bytes(&self, blowfish: &Blowfish, _: &Session) -> Vec<u8> {
        let mut packet = SendablePacket::new();
        packet.write_uint8(0x07);
        packet.write_int32(self.play_ok1);
        packet.write_int32(self.play_ok2);
        packet.pad_bits();
        packet.add_checksum();
        packet.blowfish_encrypt(blowfish);

        packet.to_bytes()
    }
}
