use crate::packet::client::{AuthGameGuardPacket, PacketTypeEnum};
use crate::packet::server::login_fail::{LoginFailPacket, LoginFailReason};
use crate::packet::server::{FromDecryptedPacket, GGAuthPacket, ServerPacketBytes};
use shared::crypto::blowfish::{decrypt_packet, encrypt_packet};
use shared::extcrypto::blowfish::Blowfish;
use shared::network::stream::Streamable;
use shared::network::{read_packet, send_packet};
use shared::structs::session::ServerSession;
use std::io::ErrorKind::InvalidData;
use std::io::{Error, Result};

pub async fn handle_gameguard_auth(
    stream: &mut impl Streamable,
    session: &ServerSession,
) -> Result<()> {
    let mut packet = read_packet(stream).await?;
    decrypt_packet(&mut packet, &Blowfish::new(&session.blowfish_key));
    let mut packet = match PacketTypeEnum::from_packet(&packet) {
        Some(PacketTypeEnum::AuthGameGuard) => {
            let packet = AuthGameGuardPacket::from_decrypted_packet(packet, None)?;
            if session.session_id != packet.get_session_id() {
                let mut packet =
                    LoginFailPacket::new(LoginFailReason::AccessFailed).to_bytes(None)?;
                encrypt_packet(&mut packet, &Blowfish::new(&session.blowfish_key));
                send_packet(stream, packet).await?;

                return Err(Error::new(InvalidData, "Session mismatch detected."));
            }
            let session_id = packet.get_session_id();
            GGAuthPacket::new(session_id).to_bytes(None).unwrap()
        }
        None | Some(_) => {
            return Err(Error::new(
                InvalidData,
                "Did not receive AuthGameGuard packet.",
            ));
        }
    };

    encrypt_packet(&mut packet, &Blowfish::new(&session.blowfish_key));
    send_packet(stream, packet).await?;

    Ok(())
}
