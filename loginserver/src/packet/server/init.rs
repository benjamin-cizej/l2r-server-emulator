use shared::crypto::Scramble;
use shared::extcrypto::blowfish::Blowfish;
use shared::network::serverpacket::{ServerPacket, ServerPacketOutputtable};
use shared::structs::session::Session;

pub struct InitPacket {
    session_id: u32,
    protocol: i32,
    scrambled_modulus: Vec<u8>,
    blowfish_key: [u8; 16],
}

impl InitPacket {
    pub fn new(session: &Session) -> InitPacket {
        InitPacket {
            session_id: session.session_id,
            protocol: 0xc621,
            scrambled_modulus: session.rsa_key.scramble_modulus(),
            blowfish_key: session.blowfish_key,
        }
    }
}

impl ServerPacketOutputtable for InitPacket {
    fn to_output_stream(&self) -> Vec<u8> {
        let blowfish = Blowfish::new(&[
            0x6b, 0x60, 0xcb, 0x5b, 0x82, 0xce, 0x90, 0xb1, 0xcc, 0x2b, 0x6c, 0x55, 0x6c, 0x6c,
            0x6c, 0x6c,
        ]);
        let mut packet = ServerPacket::new();

        packet.write_uint8(0x00);
        packet.write_int32(self.session_id as i32);
        packet.write_int32(self.protocol);
        packet.write_bytes(self.scrambled_modulus.clone());
        packet.write_int32(0);
        packet.write_int32(0);
        packet.write_int32(0);
        packet.write_int32(0);
        packet.write_bytes(Vec::from(self.blowfish_key));
        packet.write_uint8(0);
        packet.write_bytes(Vec::from([0u8; 14]));
        packet.auth_encypher();
        packet.pad_bits();
        packet.blowfish_encrypt(blowfish);

        packet.prep_output()
    }
}
