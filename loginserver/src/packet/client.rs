mod auth_gameguard;
mod request_auth_login;

pub use auth_gameguard::AuthGameGuardPacket;
pub use request_auth_login::RequestAuthLoginPacket;

use shared::extcrypto::blowfish::Blowfish;
use shared::extcrypto::symmetriccipher::BlockDecryptor;
use shared::network::serverpacket::swap32;
use shared::num::ToPrimitive;
use shared::tokio::io::AsyncReadExt;
use shared::tokio::net::TcpStream;
use std::io;
use std::io::ErrorKind::ConnectionAborted;

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
    fn from_decrypted_packet(packet: Vec<u8>) -> Self;
}

pub async fn decrypt_packet(stream: &mut TcpStream, blowfish: &Blowfish) -> io::Result<Vec<u8>> {
    let mut len = [0u8; 2];
    match stream.read(&mut len).await {
        Ok(0) => {
            return Err(io::Error::from(ConnectionAborted));
        }
        Ok(_) => {}
        Err(e) => {
            return Err(e);
        }
    }

    let mut data = vec![0; u16::from_le_bytes(len).to_usize().unwrap()];
    stream.read(&mut data).await.unwrap();

    let mut decrypted_stream: Vec<u8> = vec![];
    for i in data.chunks(8) {
        let mut dec_buffer = [0u8; 8];
        let mut input = swap32(i);
        blowfish.decrypt_block(&mut input, &mut dec_buffer);
        decrypted_stream.append(&mut Vec::from(swap32(&mut dec_buffer)));
    }

    Ok(decrypted_stream)
}
