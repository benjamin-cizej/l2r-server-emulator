use shared::extcrypto::blowfish::Blowfish;
use shared::network::serverpacket::{ServerPacket, ServerPacketOutput};
use shared::structs::server::Server;

pub struct ServerListPacket {
    pub list: Vec<Server>,
    blowfish: Blowfish,
}

impl ServerListPacket {
    pub fn new(blowfish: &Blowfish) -> ServerListPacket {
        ServerListPacket {
            list: vec![],
            blowfish: blowfish.clone(),
        }
    }
}

impl ServerPacketOutput for ServerListPacket {
    fn to_output_stream(&self) -> Vec<u8> {
        let mut packet = ServerPacket::new();
        packet.write_uint8(0x04);
        packet.write_uint8(self.list.len() as u8);
        match self.list.get(0) {
            Some(server) => {
                packet.write_uint8(server.id);
            }
            None => {
                packet.write_uint8(0);
            }
        }

        for server in self.list.iter() {
            packet.write_uint8(server.id);
            packet.write_bytes(Vec::from(server.ip.octets()));
            packet.write_int32(server.port);
            packet.write_uint8(server.age_limit as u8);
            packet.write_uint8(server.pvp_enabled as u8);
            packet.write_uint16(server.current_players);
            packet.write_uint16(server.max_players);
            packet.write_uint8(server.status as u8);
            packet.write_int32(server.server_type);
            packet.write_uint8(server.brackets as u8);
        }

        packet.write_uint16(0);
        packet.pad_bits();
        packet.add_checksum();
        packet.blowfish_encrypt(self.blowfish);

        packet.prep_output()
    }
}
