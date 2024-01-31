use shared::extcrypto::blowfish::Blowfish;
use shared::network::packet::sendable::{SendablePacket, SendablePacketBytes};

pub struct LoginOkPacket {
    pub login_ok1: i32,
    pub login_ok2: i32,
}

impl LoginOkPacket {
    pub fn new(login_ok1: i32, login_ok2: i32) -> LoginOkPacket {
        LoginOkPacket {
            login_ok1,
            login_ok2,
        }
    }
}

impl SendablePacketBytes for LoginOkPacket {
    fn to_bytes(&self, blowfish: &Blowfish) -> Vec<u8> {
        let mut packet = SendablePacket::new();
        packet.write_uint8(0x03);
        packet.write_int32(self.login_ok1);
        packet.write_int32(self.login_ok2);
        packet.pad_bits();
        packet.add_checksum();
        packet.blowfish_encrypt(blowfish);

        packet.to_bytes()
    }
}
