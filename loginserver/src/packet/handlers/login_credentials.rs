use crate::login_server::{AccountsList, MessageAction};
use crate::packet::client::{PacketTypeEnum, RequestAuthLoginPacket};
use crate::packet::server::login_fail::{LoginFailPacket, LoginFailReason};
use crate::packet::server::{FromDecryptedPacket, LoginOkPacket, ServerPacketBytes};
use shared::crypto::blowfish::{decrypt_packet, encrypt_packet};
use shared::extcrypto::blowfish::Blowfish;
use shared::network::stream::Streamable;
use shared::network::{read_packet, send_packet};
use shared::structs::session::ServerSession;
use std::io::ErrorKind::{AlreadyExists, InvalidData};
use std::io::{Error, Result};

pub async fn handle_login_credentials(
    stream: &mut impl Streamable,
    session: &ServerSession,
    accounts: &AccountsList,
) -> Result<String> {
    let mut packet = read_packet(stream).await?;
    decrypt_packet(&mut packet, &Blowfish::new(&session.blowfish_key));

    let packet = match PacketTypeEnum::from_packet(&packet) {
        Some(PacketTypeEnum::RequestAuthLogin) => {
            RequestAuthLoginPacket::from_decrypted_packet(packet, Some(&session))?
        }
        None | Some(_) => {
            return Err(Error::new(
                InvalidData,
                "Did not receive RequestAuthLogin packet.",
            ));
        }
    };

    let (mut response, result) = verify_auth(packet, &session, &accounts).await?;
    encrypt_packet(&mut response, &Blowfish::new(&session.blowfish_key));
    send_packet(stream, response).await?;

    result
}

async fn verify_auth(
    packet: RequestAuthLoginPacket,
    session: &ServerSession,
    accounts: &AccountsList,
) -> Result<(Vec<u8>, Result<String>)> {
    if packet.get_session_id() != session.session_id {
        let packet = LoginFailPacket::new(LoginFailReason::AccessFailed).to_bytes(None)?;
        return Ok((
            packet,
            Err(Error::new(InvalidData, "Session mismatch detected.")),
        ));
    }

    let account = packet.get_username();
    match accounts.lock().await.get(&account) {
        Some(sender) => {
            let packet = LoginFailPacket::new(LoginFailReason::AccountInUse).to_bytes(None)?;
            sender
                .send((MessageAction::Disconnect, packet.clone()))
                .unwrap();
            Ok((packet, Err(Error::from(AlreadyExists))))
        }
        None => {
            let packet = LoginOkPacket::new(0, 0).to_bytes(None)?;
            Ok((packet, Ok(account)))
        }
    }
}
