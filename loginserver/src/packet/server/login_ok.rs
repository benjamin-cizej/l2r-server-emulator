use shared::extcrypto::blowfish::Blowfish;
use shared::network::packet::sendable_packet::{SendablePacket, SendablePacketBytes};

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

impl SendablePacketBytes for LoginOkPacket {
    fn to_bytes(&self) -> Vec<u8> {
        let mut packet = SendablePacket::new();
        packet.write_uint8(0x03);
        packet.write_int32(self.login_ok1);
        packet.write_int32(self.login_ok2);
        packet.pad_bits();
        packet.add_checksum();
        packet.blowfish_encrypt(self.blowfish);

        packet.to_bytes()
    }
}
