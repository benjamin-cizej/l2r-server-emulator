use crate::packet::client::{AuthGameGuardPacket, PacketTypeEnum};
use crate::structs::connected_client::{ConnectedClient, LoginClientPackets};
pub use gg_auth::GGAuthPacket;
pub use init::InitPacket;
pub use login_ok::LoginOkPacket;
pub use play_ok::PlayOkPacket;
pub use server_list::ServerListPacket;
use shared::network::stream::Streamable;
use shared::rand::{thread_rng, Rng};
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

pub async fn handle_packet(client: &mut ConnectedClient<impl Streamable>) -> io::Result<()> {
    let packet = client.read_packet().await?;
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
        PacketTypeEnum::RequestAuthLogin => {
            let mut rnd = thread_rng();
            Box::new(LoginOkPacket::new(rnd.gen(), rnd.gen()))
        }
        PacketTypeEnum::AuthGameGuard => {
            let packet = AuthGameGuardPacket::from_decrypted_packet(packet, None)?;
            let packet = GGAuthPacket::new(packet.get_session_id());
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
        PacketTypeEnum::RequestServerLogin => {
            let mut rnd = thread_rng();
            Box::new(PlayOkPacket::new(rnd.gen(), rnd.gen()))
        }
    };

    client.send_packet(matched_packet).await?;
    Ok(())
}

pub type ServerPacketOutput = Box<dyn ServerPacketBytes + Send>;

pub trait ServerPacketBytes {
    fn to_bytes(&self, session: Option<&ServerSession>) -> io::Result<Vec<u8>>;
}
