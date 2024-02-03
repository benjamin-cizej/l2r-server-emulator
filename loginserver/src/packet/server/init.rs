use crate::packet::client::FromDecryptedPacket;
use crate::packet::server::ServerPacketBytes;
use shared::network::packet::receivable::ReceivablePacket;
use shared::network::packet::sendable::SendablePacket;
use shared::rand::{thread_rng, Rng};
use shared::rsa::PublicKeyParts;
use shared::structs::modulus::{RsaKeyModulus, Scramble};
use shared::structs::session::{ClientSession, ServerSession};
use shared::tokio::io;
use std::net::SocketAddr;

pub struct InitPacket {
    session_id: i32,
    protocol: i32,
    modulus: RsaKeyModulus,
    blowfish_key: [u8; 16],
}

impl InitPacket {
    pub fn new(session: &ServerSession) -> InitPacket {
        InitPacket {
            session_id: session.session_id,
            protocol: 0xc621,
            modulus: RsaKeyModulus::new(session.rsa_key.n().clone()),
            blowfish_key: session.blowfish_key,
        }
    }

    pub fn get_session_id(&self) -> i32 {
        self.session_id.clone()
    }

    pub fn get_protocol(&self) -> i32 {
        self.protocol.clone()
    }

    pub fn get_modulus(&self) -> &RsaKeyModulus {
        &self.modulus
    }

    pub fn get_blowfish_key(&self) -> [u8; 16] {
        self.blowfish_key.clone()
    }

    pub fn to_client_session(self, addr: SocketAddr) -> ClientSession {
        ClientSession {
            session_id: self.session_id,
            addr,
            modulus: self.modulus.to_value(),
            blowfish_key: self.blowfish_key,
        }
    }
}

impl ServerPacketBytes for InitPacket {
    fn to_bytes(&self, _: Option<&ServerSession>) -> io::Result<Vec<u8>> {
        let mut packet = SendablePacket::new();
        packet.write_uint8(0x00);
        packet.write_int32(self.session_id);
        packet.write_int32(self.protocol);
        packet.write_bytes(self.modulus.scramble_modulus());
        packet.write_int32(0);
        packet.write_int32(0);
        packet.write_int32(0);
        packet.write_int32(0);
        packet.write_bytes(Vec::from(self.blowfish_key));
        packet.write_uint8(0);
        packet.write_bytes(vec![0u8; 14]);
        packet.auth_encypher(thread_rng().gen());

        Ok(packet.to_vec())
    }
}

impl FromDecryptedPacket for InitPacket {
    fn from_decrypted_packet(packet: Vec<u8>, _: Option<&ClientSession>) -> io::Result<Self> {
        let mut packet = ReceivablePacket::new(packet);
        packet.auth_decypher()?;
        packet.read_uint8()?;

        let session_id = packet.read_int32()?;
        let protocol = packet.read_int32()?;
        let modulus = RsaKeyModulus::from_scrambled_bytes(packet.read_raw(128)?);

        packet.read_int32()?;
        packet.read_int32()?;
        packet.read_int32()?;
        packet.read_int32()?;

        let blowfish_key = packet.read_raw(16)?.as_mut_slice().to_owned();

        Ok(InitPacket {
            session_id,
            protocol,
            modulus,
            blowfish_key: blowfish_key.try_into().unwrap(),
        })
    }
}
