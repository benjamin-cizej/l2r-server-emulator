use crate::crypto::credentials;
use crate::crypto::credentials::encrypt_credentials;
use crate::packet::client::ClientPacketBytes;
use shared::network::packet::sendable::SendablePacket;
use shared::structs::session::{ClientSession, ServerSession};
use shared::tokio::io;
use std::io::ErrorKind::{InvalidData, Other};

use crate::packet::server::FromDecryptedPacket;

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
}

impl FromDecryptedPacket for RequestAuthLoginPacket {
    fn from_decrypted_packet(
        packet: Vec<u8>,
        session: Option<&ServerSession>,
    ) -> io::Result<RequestAuthLoginPacket> {
        let session = match session {
            Some(session) => session,
            None => return Err(io::Error::new(Other, "Session must be provided.")),
        };

        let credentials = match packet.get(1..129) {
            Some(result) => result,
            None => {
                return Err(io::Error::new(
                    InvalidData,
                    "Could not read credentials from packet.",
                ))
            }
        };
        let (username, password) =
            credentials::decrypt_credentials(credentials.try_into().unwrap(), &session.rsa_key)?;

        let session_id = match packet.get(129..133) {
            None => {
                return Err(io::Error::new(
                    InvalidData,
                    "Could not read session id from packet.",
                ))
            }
            Some(result) => i32::from_le_bytes(result.try_into().unwrap()),
        };

        Ok(RequestAuthLoginPacket {
            username,
            password,
            session_id,
        })
    }
}

impl ClientPacketBytes for RequestAuthLoginPacket {
    fn to_bytes(&self, session: Option<&ClientSession>) -> io::Result<Vec<u8>> {
        let session = match session {
            Some(session) => session,
            None => return Err(io::Error::new(Other, "Session must be provided.")),
        };

        let mut packet = SendablePacket::new();
        packet.write_uint8(0x00);
        packet.write_bytes(
            encrypt_credentials(&self.username, &self.password, &session.modulus)?
                .try_into()
                .unwrap(),
        );
        packet.write_int32(self.session_id);
        packet.write_bytes(vec![
            0x23, 0x01, 0x00, 0x00, 0x67, 0x45, 0x00, 0x00, 0xab, 0x89, 0x00, 0x00, 0xef, 0xcd,
            0x00, 0x00,
        ]);
        packet.write_bytes(vec![
            0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]);
        packet.write_bytes(vec![0u8; 16]);

        Ok(packet.to_vec())
    }
}
