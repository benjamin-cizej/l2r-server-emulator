use crate::packet::server::ServerPacketBytes;
use shared::network::packet::sendable::SendablePacket;
use shared::structs::session::ServerSession;
use std::io;

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

impl ServerPacketBytes for LoginOkPacket {
    fn to_bytes(&self, _: Option<&ServerSession>) -> io::Result<Vec<u8>> {
        let mut packet = SendablePacket::new();
        packet.write_uint8(0x03);
        packet.write_int32(self.login_ok1);
        packet.write_int32(self.login_ok2);
        packet.write_bytes(vec![0u8; 7]);
        packet.add_checksum();

        Ok(packet.to_vec())
    }
}
