use shared::crypto::blowfish::StaticL2Blowfish;
use crate::packet::client::FromDecryptedPacket;
use shared::extcrypto::blowfish::Blowfish;
use shared::network::packet::sendable_packet::{SendablePacket, SendablePacketBytes};
use shared::rsa::{BigUint, PublicKeyParts};
use shared::structs::modulus::{RsaKeyModulus, Scramble};
use shared::structs::session::Session;

pub struct InitPacket {
    session_id: u32,
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

    pub fn get_session_id(&self) -> &u32 {
        &self.session_id
    }

    pub fn get_protocol(&self) -> &i32 {
        &self.protocol
    }

    pub fn get_modulus(&self) -> &RsaKeyModulus {
        &self.modulus
    }

    pub fn get_blowfish_key(&self) -> &[u8; 16] {
        &self.blowfish_key
    }
}

impl SendablePacketBytes for InitPacket {
    fn to_bytes(&self) -> Vec<u8> {
        let blowfish = Blowfish::new_l2_static();
        let mut packet = SendablePacket::new();

        packet.write_uint8(0x00);
        packet.write_int32(self.session_id as i32);
        packet.write_int32(self.protocol);
        packet.write_bytes(self.modulus.scramble_modulus());
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

        packet.to_bytes()
    }
}

impl FromDecryptedPacket for InitPacket {
    fn from_decrypted_packet(packet: Vec<u8>) -> Self {
        let mut blowfish_key: [u8; 16] = packet.get(154..170).unwrap().try_into().unwrap();
        blowfish_key.reverse();

        InitPacket {
            session_id: u32::from_le_bytes(packet.get(1..5).unwrap().try_into().unwrap()),
            modulus: RsaKeyModulus::new(BigUint::from_bytes_le(
                packet.get(10..138).unwrap().try_into().unwrap(),
            )),
            protocol: i32::from_le_bytes(packet.get(5..9).unwrap().try_into().unwrap()),
            blowfish_key,
        }
    }
}
