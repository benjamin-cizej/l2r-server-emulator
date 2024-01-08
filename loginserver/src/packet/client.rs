pub mod login;

use shared::extcrypto::blowfish::Blowfish;
use shared::extcrypto::symmetriccipher::BlockDecryptor;
use shared::network::serverpacket::swap32;
use shared::num::ToPrimitive;
use std::io;
use std::io::ErrorKind::ConnectionAborted;
use std::io::Read;
use std::net::TcpStream;

pub enum LoginClientPacketEnum {
    RequestServerLogin,
    RequestAuthLogin,
    AuthGameGuard,
    ServerList,
}

impl LoginClientPacketEnum {
    pub fn from(opcode: &u8) -> Option<LoginClientPacketEnum> {
        match opcode {
            0x02 => Some(LoginClientPacketEnum::RequestServerLogin),
            0x00 => Some(LoginClientPacketEnum::RequestAuthLogin),
            0x07 => Some(LoginClientPacketEnum::AuthGameGuard),
            0x05 => Some(LoginClientPacketEnum::ServerList),
            _ => None,
        }
    }

    pub fn from_packet(packet: &Vec<u8>) -> Option<LoginClientPacketEnum> {
        return match packet.get(0) {
            Some(opcode) => LoginClientPacketEnum::from(opcode),
            None => None,
        };
    }
}

pub trait FromDecryptedPacket {
    fn from_decrypted_packet(packet: Vec<u8>) -> Self;
}

pub fn decrypt_login_packet(stream: &mut TcpStream, blowfish: &Blowfish) -> io::Result<Vec<u8>> {
    let mut len = [0u8; 2];
    match stream.read(&mut len) {
        Ok(0) => {
            return Err(io::Error::from(ConnectionAborted));
        }
        Ok(_) => {}
        Err(e) => {
            return Err(e);
        }
    }

    let mut data = vec![0; u16::from_le_bytes(len).to_usize().unwrap()];
    stream.read(&mut data).unwrap();

    let mut decrypted_stream: Vec<u8> = vec![];
    for i in data.chunks(8) {
        let mut dec_buffer = [0u8; 8];
        let mut input = swap32(i);
        blowfish.decrypt_block(&mut input, &mut dec_buffer);
        decrypted_stream.append(&mut Vec::from(swap32(&mut dec_buffer)));
    }

    Ok(decrypted_stream)
}
