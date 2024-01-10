use shared::extcrypto::blowfish::Blowfish;
use shared::network::serverpacket::{ServerPacket, ServerPacketOutput};

pub struct LoginOkPacket {
    pub login_ok1: i32,
    pub login_ok2: i32,
    blowfish: Blowfish,
}

impl LoginOkPacket {
    pub fn new(blowfish: &Blowfish) -> LoginOkPacket {
        LoginOkPacket {
            login_ok1: 0,
            login_ok2: 0,
            blowfish: blowfish.clone(),
        }
    }
}

impl ServerPacketOutput for LoginOkPacket {
    fn to_output_stream(&self) -> Vec<u8> {
        let mut packet = ServerPacket::new();
        packet.write_uint8(0x03);
        packet.write_int32(self.login_ok1);
        packet.write_int32(self.login_ok2);
        packet.pad_bits();
        packet.add_checksum();
        packet.blowfish_encrypt(self.blowfish);

        packet.prep_output()
    }
}
