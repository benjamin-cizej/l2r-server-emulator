use crate::packet::client::FromDecryptedPacket;
use shared::extcrypto::blowfish::Blowfish;
use shared::network::packet::receivable::ReceivablePacket;
use shared::network::packet::sendable::{SendablePacket, SendablePacketBytes};
use shared::rand::{thread_rng, Rng};
use shared::rsa::PublicKeyParts;
use shared::structs::modulus::{RsaKeyModulus, Scramble};
use shared::structs::session::Session;

pub struct InitPacket {
    session_id: i32,
    protocol: i32,
    modulus: RsaKeyModulus,
    blowfish_key: [u8; 16],
}

impl InitPacket {
    pub fn new(session: &Session) -> InitPacket {
        InitPacket {
            session_id: session.session_id,
            protocol: 0xc621,
            modulus: RsaKeyModulus::new(session.rsa_key.to_public_key().n().clone()),
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
}

impl SendablePacketBytes for InitPacket {
    fn to_bytes(&self, blowfish: &Blowfish) -> Vec<u8> {
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
        packet.blowfish_encrypt(blowfish);

        packet.to_bytes()
    }
}

impl FromDecryptedPacket for InitPacket {
    fn from_decrypted_packet(packet: Vec<u8>) -> Self {
        let mut packet = ReceivablePacket::new(packet);
        packet.auth_decypher().unwrap();
        packet.read_uint8().unwrap();

        let session_id = packet.read_int32().unwrap();
        let protocol = packet.read_int32().unwrap();
        let modulus = RsaKeyModulus::from_scrambled_bytes(packet.read_raw(128).unwrap());

        packet.read_int32().unwrap();
        packet.read_int32().unwrap();
        packet.read_int32().unwrap();
        packet.read_int32().unwrap();

        let blowfish_key = packet.read_raw(16).unwrap().as_mut_slice().to_owned();

        InitPacket {
            session_id,
            protocol,
            modulus,
            blowfish_key: blowfish_key.try_into().unwrap(),
        }
    }
}
