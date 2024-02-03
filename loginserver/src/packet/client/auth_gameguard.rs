use crate::packet::client::ClientPacketBytes;
use crate::packet::server::FromDecryptedPacket;
use shared::network::packet::receivable::ReceivablePacket;
use shared::network::packet::sendable::SendablePacket;
use shared::structs::session::{ClientSession, ServerSession};
use shared::tokio::io;
use std::io::{ErrorKind::Other, Result};

pub struct AuthGameGuardPacket {
    session_id: i32,
}

impl AuthGameGuardPacket {
    pub fn new(session_id: i32) -> Self {
        AuthGameGuardPacket { session_id }
    }

    pub fn get_session_id(self) -> i32 {
        self.session_id
    }
}

impl FromDecryptedPacket for AuthGameGuardPacket {
    fn from_decrypted_packet(
        packet: Vec<u8>,
        _: Option<&ServerSession>,
    ) -> Result<AuthGameGuardPacket> {
        let mut packet = ReceivablePacket::new(packet);
        packet.read_uint8()?;
        let session_id = packet.read_int32()?;

        Ok(AuthGameGuardPacket { session_id })
    }
}

impl ClientPacketBytes for AuthGameGuardPacket {
    fn to_bytes(&self, session: Option<&ClientSession>) -> Result<Vec<u8>> {
        let session = match session {
            Some(session) => session,
            None => return Err(io::Error::new(Other, "Session must be provided.")),
        };

        let mut packet = SendablePacket::new();
        packet.write_uint8(0x07);
        packet.write_int32(session.session_id);
        packet.write_int32(0);
        packet.write_int32(0);
        packet.write_int32(0);
        packet.write_int32(0);
        packet.write_bytes(vec![0u8; 19]);

        Ok(packet.to_vec())
    }
}
