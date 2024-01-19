use std::collections::HashMap;
use std::io::{Error, Result};
use std::io::ErrorKind::{AlreadyExists, InvalidData, Unsupported};
use std::sync::Arc;

use shared::extcrypto::blowfish::Blowfish;
use shared::network::{read_packet, send_packet};
use shared::network::serverpacket::ServerPacketOutput;
use shared::structs::session::Session;
use shared::tokio::net::TcpStream;
use shared::tokio::sync::broadcast::Sender;
use shared::tokio::sync::Mutex;

use crate::MessageAction;
use crate::packet::client::{
    AuthGameGuardPacket, decrypt_packet, FromDecryptedPacket, PacketTypeEnum,
    RequestAuthLoginPacket,
};
use crate::packet::server::{GGAuthPacket, LoginOkPacket};
use crate::packet::server::login_fail::{LoginFailPacket, LoginFailReason};

pub async fn handle_gameguard_auth(stream: &mut TcpStream, blowfish: &Blowfish) -> Result<()> {
    let packet = read_packet(stream).await?;
    let decrypted_packet = decrypt_packet(packet, &blowfish);
    let packet: ServerPacketOutput = match PacketTypeEnum::from_packet(&decrypted_packet) {
        None => {
            return Err(Error::new(
                Unsupported,
                format!("0x{:02X}", decrypted_packet.get(0).unwrap()),
            ));
        }
        Some(PacketTypeEnum::AuthGameGuard) => {
            let packet = AuthGameGuardPacket::from_decrypted_packet(decrypted_packet);
            let session_id = packet.get_session_id();
            let mut packet = GGAuthPacket::new(&blowfish);
            packet.session_id = session_id;

            Box::new(packet)
        }
        Some(_) => {
            return Err(Error::new(
                InvalidData,
                "Did not receive AuthGameGuard packet",
            ));
        }
    };

    send_packet(stream, packet).await?;

    Ok(())
}

pub async fn handle_login_credentials(
    stream: &mut TcpStream,
    blowfish: &Blowfish,
    session: &Session,
    accounts: &Arc<Mutex<HashMap<String, Sender<(MessageAction, Vec<u8>)>>>>,
) -> Result<String> {
    let packet = read_packet(stream).await?;
    let mut decrypted_packet = decrypt_packet(packet, &blowfish);
    let account: String;
    let packet: ServerPacketOutput = match PacketTypeEnum::from_packet(&decrypted_packet) {
        None => {
            return Err(Error::new(
                Unsupported,
                format!("0x{:02X}", decrypted_packet.get(0).unwrap()),
            ));
        }
        Some(PacketTypeEnum::RequestAuthLogin) => {
            RequestAuthLoginPacket::decrypt_credentials(&mut decrypted_packet, &session)?;
            let packet = RequestAuthLoginPacket::from_decrypted_packet(decrypted_packet);
            account = packet.get_username();
            println!("dec acc {}", account);
            if let Some(sender) = accounts.lock().await.get(&account) {
                let packet: ServerPacketOutput = Box::new(LoginFailPacket::new(
                    LoginFailReason::AccountInUse,
                    &blowfish,
                ));
                sender
                    .send((MessageAction::Disconnect, packet.to_output_stream()))
                    .unwrap();
                return Err(Error::from(AlreadyExists));
            }

            Box::new(LoginOkPacket::new(&blowfish))
        }
        Some(_) => {
            return Err(Error::new(
                InvalidData,
                "Did not receive RequestAuthLogin packet",
            ));
        }
    };

    send_packet(stream, packet).await?;

    Ok(account)
}
