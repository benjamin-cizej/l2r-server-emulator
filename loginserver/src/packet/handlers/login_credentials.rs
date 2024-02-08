use crate::login_server::{ConnectedAccounts, MessageAction};
use crate::packet::client::{PacketTypeEnum, RequestAuthLoginPacket};
use crate::packet::server::login_fail::LoginFailReason::UserOrPassWrong;
use crate::packet::server::login_fail::{LoginFailPacket, LoginFailReason};
use crate::packet::server::{FromDecryptedPacket, LoginOkPacket, ServerPacketOutput};
use crate::repository::account::AccountRepository;
use crate::structs::account::Account;
use crate::structs::connected_client::ConnectionState::{Authorized, CredentialsAuthorization};
use crate::structs::connected_client::{ConnectedClient, LoginClientPackets};
use shared::network::stream::Streamable;
use shared::pwhash::sha512_crypt::verify;
use shared::rand::{thread_rng, Rng};
use shared::tokio::sync::Mutex;
use std::io::ErrorKind::{AlreadyExists, InvalidData};
use std::io::{Error, Result};
use std::sync::Arc;

pub async fn handle_login_credentials(
    client: &mut ConnectedClient<impl Streamable>,
    connected_accounts: &ConnectedAccounts,
    repository: &Arc<Mutex<impl AccountRepository>>,
) -> Result<String> {
    client.state = CredentialsAuthorization;
    let packet = client.read_packet().await?;
    let packet = match PacketTypeEnum::from_packet(&packet) {
        Some(PacketTypeEnum::RequestAuthLogin) => {
            RequestAuthLoginPacket::from_decrypted_packet(packet, Some(&client.session))?
        }
        None | Some(_) => {
            return Err(Error::new(
                InvalidData,
                "Did not receive RequestAuthLogin packet.",
            ));
        }
    };

    let (response, result) = verify_auth(packet, client, connected_accounts, repository).await?;
    client.send_packet(response).await?;

    result
}

async fn verify_auth(
    packet: RequestAuthLoginPacket,
    client: &mut ConnectedClient<impl Streamable>,
    connected_accounts: &ConnectedAccounts,
    repository: &Arc<Mutex<impl AccountRepository>>,
) -> Result<(ServerPacketOutput, Result<String>)> {
    if packet.get_session_id() != client.session.session_id {
        let packet = LoginFailPacket::new(LoginFailReason::AccessFailed);
        return Ok((
            Box::new(packet),
            Err(Error::new(InvalidData, "Session mismatch detected.")),
        ));
    }

    let account = {
        let mut lock = repository.lock().await;
        match lock.get(&packet.get_username())? {
            Some(account) => {
                if !verify(packet.get_password(), account.password.clone().as_str()) {
                    let packet = LoginFailPacket::new(UserOrPassWrong);
                    return Ok((
                        Box::new(packet),
                        Err(Error::new(InvalidData, "Invalid account credentials.")),
                    ));
                }

                account.username.clone()
            }
            None => {
                let account = Account::new(packet.get_username(), packet.get_password(), None);
                lock.save(&account)?;
                packet.get_username()
            }
        }
    };

    match connected_accounts.lock().await.get(&account) {
        Some(sender) => {
            let packet = LoginFailPacket::new(LoginFailReason::AccountInUse);
            sender.send(MessageAction::Disconnect).unwrap();
            Ok((Box::new(packet), Err(Error::from(AlreadyExists))))
        }
        None => {
            let mut rnd = thread_rng();
            let packet = LoginOkPacket::new(rnd.gen(), rnd.gen());
            client.state = Authorized;
            Ok((Box::new(packet), Ok(account)))
        }
    }
}
