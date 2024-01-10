use crate::packet::client::FromDecryptedPacket;
use shared::rand::thread_rng;
use shared::rsa::internals::decrypt;
use shared::rsa::BigUint;
use shared::structs::session::Session;

#[derive(Debug)]
pub struct RequestAuthLoginPacket {
    username: String,
    password: String,
    session_id: u32,
}

impl RequestAuthLoginPacket {
    pub fn get_username(&self) -> String {
        self.username.clone()
    }

    pub fn get_password(&self) -> String {
        self.password.clone()
    }

    pub fn get_session_id(&self) -> u32 {
        self.session_id
    }

    pub fn decrypt_credentials(packet: &Vec<u8>, session: &Session) {
        if let Some(credentials) = packet.get(1..129) {
            let credentials = BigUint::from_bytes_be(credentials);
            match decrypt(Some(&mut thread_rng()), &session.rsa_key, &credentials) {
                Ok(result) => {
                    let mut replacement = vec![0u8; 91];
                    replacement.append(&mut result.to_bytes_be());
                    packet.clone().splice(1..129, replacement);
                }
                Err(e) => {
                    println!("ERROR DECRYPTING {:?}", e);
                }
            };
        }
    }
}

impl FromDecryptedPacket for RequestAuthLoginPacket {
    fn from_decrypted_packet(packet: Vec<u8>) -> RequestAuthLoginPacket {
        let username = String::from_utf8_lossy(packet.get(94..109).unwrap().try_into().unwrap())
            .trim_matches(char::from(0))
            .trim()
            .to_string();

        let password = String::from_utf8_lossy(packet.get(109..128).unwrap().try_into().unwrap())
            .trim_matches(char::from(0))
            .trim()
            .to_string();

        RequestAuthLoginPacket {
            username,
            password,
            session_id: u32::from_le_bytes(packet.get(129..133).unwrap().try_into().unwrap()),
        }
    }
}