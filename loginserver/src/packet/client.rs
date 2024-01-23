use std::io::ErrorKind::Unsupported;
use std::io::{Error, Result};
use std::net::Ipv4Addr;

use crate::packet::server::{GGAuthPacket, LoginOkPacket, PlayOkPacket, ServerListPacket};
pub use auth_gameguard::AuthGameGuardPacket;
pub use request_auth_login::RequestAuthLoginPacket;
use shared::extcrypto::blowfish::Blowfish;
use shared::extcrypto::symmetriccipher::BlockDecryptor;
use shared::network::packet::sendable_packet::SendablePacketOutput;
use shared::network::packet::swap32;
use shared::network::stream::Streamable;
use shared::network::{read_packet, send_packet};
use shared::structs::server::Server;

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
    fn from_decrypted_packet(packet: Vec<u8>) -> Self;
}

pub fn decrypt_packet(packet: Vec<u8>, blowfish: &Blowfish) -> Vec<u8> {
    let mut decrypted_stream: Vec<u8> = vec![];
    for i in packet.chunks(8) {
        let mut dec_buffer = [0u8; 8];
        let mut input = swap32(i);
        blowfish.decrypt_block(&mut input, &mut dec_buffer);
        decrypted_stream.append(&mut Vec::from(swap32(&mut dec_buffer)));
    }

    decrypted_stream
}

pub async fn handle_packet(stream: &mut impl Streamable, blowfish: &Blowfish) -> Result<()> {
    let packet = read_packet(stream).await?;
    let decrypted_packet = decrypt_packet(packet, &blowfish);
    let packet_type = match PacketTypeEnum::from_packet(&decrypted_packet) {
        None => {
            return Err(Error::new(
                Unsupported,
                format!("0x{:02X}", decrypted_packet.get(0).unwrap()),
            ));
        }
        Some(packet_type) => packet_type,
    };

    let matched_packet: SendablePacketOutput = match packet_type {
        PacketTypeEnum::RequestAuthLogin => Box::new(LoginOkPacket::new(&blowfish)),
        PacketTypeEnum::AuthGameGuard => {
            let packet = AuthGameGuardPacket::from_decrypted_packet(decrypted_packet);
            let session_id = packet.get_session_id();
            let mut packet = GGAuthPacket::new(&blowfish);
            packet.session_id = session_id;

            Box::new(packet)
        }
        PacketTypeEnum::ServerList => {
            let mut packet = ServerListPacket::new(&blowfish);
            packet.list.push(Server {
                id: 1,
                ip: Ipv4Addr::new(127, 0, 0, 1),
                port: 7778,
                age_limit: false,
                pvp_enabled: true,
                current_players: 0,
                max_players: 100,
                status: true,
                server_type: 1,
                brackets: false,
            });

            Box::new(packet)
        }
        PacketTypeEnum::RequestServerLogin => Box::new(PlayOkPacket::new(&blowfish)),
    };

    send_packet(stream, matched_packet).await?;

    Ok(())
}
