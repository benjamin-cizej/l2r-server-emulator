use shared::extcrypto::blowfish::Blowfish;
use shared::network::serverpacket::{ServerPacket, ServerPacketOutput};

pub struct GGAuthPacket {
    pub session_id: u32,
    blowfish: Blowfish,
}

impl GGAuthPacket {
    pub fn new(blowfish: &Blowfish) -> GGAuthPacket {
        GGAuthPacket {
            session_id: 0,
            blowfish: blowfish.clone(),
        }
    }
}

impl ServerPacketOutput for GGAuthPacket {
    fn to_output_stream(&self) -> Vec<u8> {
        let mut packet = ServerPacket::new();
        packet.write_uint8(0x0b);
        packet.write_int32(self.session_id as i32);
        packet.write_int32(0);
        packet.write_int32(0);
        packet.write_int32(0);
        packet.write_int32(0);
        packet.pad_bits();
        packet.add_checksum();
        packet.blowfish_encrypt(self.blowfish);

        packet.prep_output()
    }
}
