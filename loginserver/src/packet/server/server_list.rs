use crate::packet::server::ServerPacketBytes;
use shared::network::packet::sendable::SendablePacket;
use shared::structs::server::Server;
use shared::structs::session::ServerSession;
use shared::tokio::io;

pub struct ServerListPacket {
    pub list: Vec<Server>,
}

impl ServerListPacket {
    pub fn new() -> ServerListPacket {
        ServerListPacket { list: vec![] }
    }
}

impl ServerPacketBytes for ServerListPacket {
    fn to_bytes(&self, _: Option<&ServerSession>) -> io::Result<Vec<u8>> {
        let mut packet = SendablePacket::new();
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

        Ok(packet.to_vec())
    }
}
