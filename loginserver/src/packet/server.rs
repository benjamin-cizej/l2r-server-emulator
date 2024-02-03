use crate::packet::client::{AuthGameGuardPacket, PacketTypeEnum};
pub use gg_auth::GGAuthPacket;
pub use init::InitPacket;
pub use login_ok::LoginOkPacket;
pub use play_ok::PlayOkPacket;
pub use server_list::ServerListPacket;
use shared::crypto::blowfish::decrypt_packet;
use shared::extcrypto::blowfish::Blowfish;
use shared::network::stream::Streamable;
use shared::network::{read_packet, send_packet};
use shared::structs::server::Server;
use shared::structs::session::ServerSession;
use std::io;
use std::io::Error;
use std::io::ErrorKind::Unsupported;
use std::net::Ipv4Addr;

mod gg_auth;
mod init;
pub mod login_fail;
mod login_ok;
mod play_ok;
mod server_list;

pub trait FromDecryptedPacket {
    fn from_decrypted_packet(packet: Vec<u8>, session: Option<&ServerSession>) -> io::Result<Self>
    where
        Self: Sized;
}

pub async fn handle_packet(
    stream: &mut impl Streamable,
    session: &ServerSession,
) -> io::Result<()> {
    let mut packet = read_packet(stream).await?;
    decrypt_packet(&mut packet, &Blowfish::new(&session.blowfish_key));
    let packet_type = match PacketTypeEnum::from_packet(&packet) {
        None => {
            return Err(Error::new(
                Unsupported,
                format!("0x{:02X}", packet.get(0).unwrap()),
            ));
        }
        Some(packet_type) => packet_type,
    };

    let matched_packet: ServerPacketOutput = match packet_type {
        PacketTypeEnum::RequestAuthLogin => Box::new(LoginOkPacket::new(0, 0)),
        PacketTypeEnum::AuthGameGuard => {
            let packet = AuthGameGuardPacket::from_decrypted_packet(packet, None)?;
            let session_id = packet.get_session_id();
            let mut packet = GGAuthPacket::new(session_id);
            packet.session_id = session_id;

            Box::new(packet)
        }
        PacketTypeEnum::ServerList => {
            let mut packet = ServerListPacket::new();
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
        PacketTypeEnum::RequestServerLogin => Box::new(PlayOkPacket::new(0, 0)),
    };

    let mut packet = matched_packet.to_bytes(Some(&session))?;
    decrypt_packet(&mut packet, &Blowfish::new(&session.blowfish_key));
    send_packet(stream, matched_packet.to_bytes(Some(&session))?).await?;

    Ok(())
}

pub type ServerPacketOutput = Box<dyn ServerPacketBytes + Send>;

pub trait ServerPacketBytes {
    fn to_bytes(&self, session: Option<&ServerSession>) -> io::Result<Vec<u8>>;
}
