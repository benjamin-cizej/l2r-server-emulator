use shared::extcrypto::blowfish::Blowfish;
use shared::network::packet::sendable_packet::{SendablePacket, SendablePacketBytes};

pub struct PlayOkPacket {
    pub play_ok1: i32,
    pub play_ok2: i32,
    blowfish: Blowfish,
}

impl PlayOkPacket {
    pub fn new(blowfish: &Blowfish) -> PlayOkPacket {
        PlayOkPacket {
            play_ok1: 0,
            play_ok2: 0,
            blowfish: blowfish.clone(),
        }
    }
}

impl SendablePacketBytes for PlayOkPacket {
    fn to_bytes(&self) -> Vec<u8> {
        let mut packet = SendablePacket::new();
        packet.write_uint8(0x07);
        packet.write_int32(self.play_ok1);
        packet.write_int32(self.play_ok2);
        packet.pad_bits();
        packet.add_checksum();
        packet.blowfish_encrypt(self.blowfish);

        packet.to_bytes()
    }
}
