use crate::packet::client::{AuthGameGuardPacket, PacketTypeEnum};
use crate::packet::server::login_fail::{LoginFailPacket, LoginFailReason};
use crate::packet::server::{FromDecryptedPacket, GGAuthPacket};
use crate::structs::connected_client::ConnectionState::{
    GameGuardAuthorization, GameGuardAuthorized,
};
use crate::structs::connected_client::{ConnectedClient, LoginClientPackets};
use shared::network::stream::Streamable;
use std::io::ErrorKind::InvalidData;
use std::io::{Error, Result};

pub async fn handle_gameguard_auth(client: &mut ConnectedClient<impl Streamable>) -> Result<()> {
    client.state = GameGuardAuthorization;
    let packet = client.read_packet().await?;
    let packet = match PacketTypeEnum::from_packet(&packet) {
        Some(PacketTypeEnum::AuthGameGuard) => {
            AuthGameGuardPacket::from_decrypted_packet(packet, None)?
        }
        None | Some(_) => {
            return Err(Error::new(
                InvalidData,
                "Did not receive AuthGameGuard packet.",
            ));
        }
    };

    if client.session.session_id != packet.get_session_id() {
        let packet = Box::new(LoginFailPacket::new(LoginFailReason::AccessFailed));
        client.send_packet(packet).await?;
        return Err(Error::new(InvalidData, "Session mismatch detected."));
    }

    let session_id = packet.get_session_id();
    let packet = Box::new(GGAuthPacket::new(session_id));
    client.send_packet(packet).await?;
    client.state = GameGuardAuthorized;
    Ok(())
}
