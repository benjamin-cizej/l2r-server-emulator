use shared::extcrypto::blowfish::Blowfish;
use shared::network::packet::receivable::ReceivablePacket;
use shared::network::packet::sendable::{SendablePacket, SendablePacketBytes};
use std::io;
use std::io::Error;
use std::io::ErrorKind::InvalidData;

use shared::rand::thread_rng;
use shared::rsa::internals::decrypt;
use shared::rsa::{BigUint, PublicKeyParts};
use shared::structs::session::Session;

use crate::packet::client::FromDecryptedPacket;

pub struct RequestAuthLoginPacket {
    username: String,
    password: String,
    session_id: i32,
}

impl RequestAuthLoginPacket {
    pub fn new(username: String, password: String, session_id: i32) -> Self {
        RequestAuthLoginPacket {
            username,
            password,
            session_id,
        }
    }

    pub fn get_username(&self) -> String {
        self.username.clone()
    }

    pub fn get_password(&self) -> String {
        self.password.clone()
    }

    pub fn get_session_id(&self) -> i32 {
        self.session_id.clone()
    }

    pub fn decrypt_credentials(packet: &mut Vec<u8>, session: &Session) -> io::Result<()> {
        let credentials = match packet.get(1..129) {
            Some(credentials) => credentials,
            None => {
                return Err(Error::new(
                    InvalidData,
                    "Could not read credentials from packet",
                ))
            }
        };

        let credentials = BigUint::from_bytes_be(credentials);
        return match decrypt(Some(&mut thread_rng()), &session.rsa_key, &credentials) {
            Ok(result) => {
                let mut replacement = vec![0u8; 91];
                replacement.append(&mut result.to_bytes_be());
                packet.splice(1..129, replacement);
                Ok(())
            }
            Err(e) => Err(Error::new(
                InvalidData,
                format!("Error decryptyng credentials: {}", e.to_string()),
            )),
        };
    }

    pub fn get_encrypted_credentials(&self, session: &Session) -> Vec<u8> {
        let mut encrypted = vec![0u8; 128];
        encrypted[0x5b] = 0x24;

        for (i, char) in self.get_username().chars().enumerate() {
            encrypted[0x5e + i] = char as u8;
        }

        for (i, char) in self.get_password().chars().enumerate() {
            encrypted[0x6c + i] = char as u8;
        }

        let e = BigUint::from(65537u32);
        let modulus = session.rsa_key.n();
        let input = BigUint::from_bytes_be(&encrypted);

        input.modpow(&e, &modulus).to_radix_be(256)
    }
}

impl SendablePacketBytes for RequestAuthLoginPacket {
    fn to_bytes(&self, blowfish: &Blowfish, session: &Session) -> Vec<u8> {
        let mut packet = SendablePacket::new();
        packet.write_uint8(0x00);
        packet.write_bytes(self.get_encrypted_credentials(session));
        packet.write_int32(session.session_id);
        packet.write_bytes(Vec::from([
            0x23, 0x01, 0x00, 0x00, 0x67, 0x45, 0x00, 0x00, 0xab, 0x89, 0x00, 0x00, 0xef, 0xcd,
            0x00, 0x00,
        ]));
        packet.write_bytes(Vec::from([
            0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]));
        packet.write_bytes(vec![0u8; 16]);
        packet.blowfish_encrypt(blowfish);

        packet.to_bytes()
    }
}

impl FromDecryptedPacket for RequestAuthLoginPacket {
    fn from_decrypted_packet(packet: Vec<u8>) -> RequestAuthLoginPacket {
        let mut packet = ReceivablePacket::new(packet);
        packet.read_uint8().unwrap();
        packet.read_raw(94).unwrap();
        let username = packet.read_text(14).unwrap();
        let password = packet.read_text(16).unwrap();
        packet.read_raw(4).unwrap();
        let session_id = packet.read_int32().unwrap();

        RequestAuthLoginPacket {
            username,
            password,
            session_id,
        }
    }
}
