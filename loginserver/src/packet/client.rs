pub use auth_gameguard::AuthGameGuardPacket;
pub use request_auth_login::RequestAuthLoginPacket;
use shared::structs::session::ClientSession;
use std::io::Result;

mod auth_gameguard;
mod request_auth_login;

pub enum PacketTypeEnum {
    RequestServerLogin,
    RequestAuthLogin,
    AuthGameGuard,
    ServerList,
}

impl PacketTypeEnum {
    pub fn from(opcode: &u8) -> Option<PacketTypeEnum> {
        match opcode {
            0x02 => Some(PacketTypeEnum::RequestServerLogin),
            0x00 => Some(PacketTypeEnum::RequestAuthLogin),
            0x07 => Some(PacketTypeEnum::AuthGameGuard),
            0x05 => Some(PacketTypeEnum::ServerList),
            _ => None,
        }
    }

    pub fn from_packet(packet: &Vec<u8>) -> Option<PacketTypeEnum> {
        return match packet.get(0) {
            Some(opcode) => PacketTypeEnum::from(opcode),
            None => None,
        };
    }
}

pub trait FromDecryptedPacket {
    fn from_decrypted_packet(packet: Vec<u8>, session: Option<&ClientSession>) -> Result<Self>
    where
        Self: Sized;
}

pub type ClientPacketOutput = Box<dyn ClientPacketBytes + Send>;

pub trait ClientPacketBytes {
    fn to_bytes(&self, session: Option<&ClientSession>) -> Result<Vec<u8>>;
}
