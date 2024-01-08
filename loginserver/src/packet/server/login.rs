use crate::packet::server::ServerPacketOutput;
use shared::crypto::Scramble;
use shared::extcrypto::blowfish::Blowfish;
use shared::network::serverpacket::ServerPacket;
use shared::structs::server::Server;
use shared::structs::session::Session;

pub struct InitPacket {
    pub session_id: u32,
    pub protocol: i32,
    pub scrambled_modulus: Vec<u8>,
    pub blowfish_key: [u8; 16],
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

impl ServerPacketOutput for InitPacket {
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

pub struct AuthGameGuardPacket {
    pub session_id: u32,
    blowfish: Blowfish,
}

impl AuthGameGuardPacket {
    pub fn new(blowfish: &Blowfish) -> AuthGameGuardPacket {
        AuthGameGuardPacket {
            session_id: 0,
            blowfish: blowfish.clone(),
        }
    }
}

impl ServerPacketOutput for AuthGameGuardPacket {
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

impl ServerPacketOutput for PlayOkPacket {
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
