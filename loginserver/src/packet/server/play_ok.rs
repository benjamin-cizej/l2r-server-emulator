use shared::extcrypto::blowfish::Blowfish;
use shared::network::serverpacket::{ServerPacket, ServerPacketOutputtable};

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

impl ServerPacketOutputtable for PlayOkPacket {
    fn to_output_stream(&self) -> Vec<u8> {
        let mut packet = ServerPacket::new();
        packet.write_uint8(0x07);
        packet.write_int32(self.play_ok1);
        packet.write_int32(self.play_ok2);
        packet.pad_bits();
        packet.add_checksum();
        packet.blowfish_encrypt(self.blowfish);

        packet.prep_output()
    }
}
