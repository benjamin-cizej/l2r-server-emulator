use client::Client;
use loginserver::login_server::{ConnectedAccounts, MessageAction};
use loginserver::packet::client::{FromDecryptedPacket, RequestAuthLoginPacket};
use loginserver::packet::handlers::login_credentials::handle_login_credentials;
use loginserver::packet::server::login_fail::LoginFailPacket;
use loginserver::packet::server::login_fail::LoginFailReason::{AccessFailed, UserOrPassWrong};
use loginserver::packet::server::LoginOkPacket;
use loginserver::repository::account::AccountRepository;
use loginserver::repository::memory::account::InMemoryAccountRepository;
use loginserver::structs::account::Account;
use loginserver::structs::connected_client::ConnectedClient;
use loginserver::structs::connected_client::ConnectionState::CredentialsAuthorization;
use shared::network::channel::channel_stream::ChannelStream;
use shared::network::packet::prepend_length;
use shared::tokio;
use shared::tokio::sync::broadcast::Sender;
use shared::tokio::sync::Mutex;
use std::collections::HashMap;
use std::io::ErrorKind::{ConnectionAborted, InvalidData};
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use tests::mocks::stream::MockStream;

#[tokio::test]
async fn it_returns_error_on_closed_connection() {
    let mut connected_client = ConnectedClient::new(
        MockStream::new(vec![]),
        SocketAddr::from_str("127.0.0.1:0").unwrap(),
    );
    connected_client.state = CredentialsAuthorization;

    let accounts: ConnectedAccounts =
        Arc::new(Mutex::new(HashMap::<String, Sender<MessageAction>>::new()));
    let storage = Arc::new(Mutex::new(InMemoryAccountRepository::new()));
    let error = handle_login_credentials(&mut connected_client, &accounts, &storage)
        .await
        .unwrap_err();
    assert_eq!(ConnectionAborted, error.kind());
}

#[tokio::test]
async fn it_returns_error_on_invalid_packet_received() {
    let mut buffer = vec![0; 16];
    prepend_length(&mut buffer);
    let mut client = ConnectedClient::new(
        MockStream::new(buffer),
        SocketAddr::from_str("127.0.0.1:0").unwrap(),
    );
    client.state = CredentialsAuthorization;

    let clients: ConnectedAccounts =
        Arc::new(Mutex::new(HashMap::<String, Sender<MessageAction>>::new()));
    let storage = Arc::new(Mutex::new(InMemoryAccountRepository::new()));

    let error = handle_login_credentials(&mut client, &clients, &storage)
        .await
        .unwrap_err();
    assert_eq!(InvalidData, error.kind());
    assert_eq!(
        "Did not receive RequestAuthLogin packet.",
        error.to_string()
    );
}

#[tokio::test]
async fn it_returns_error_on_session_id_mismatch() {
    let clients: ConnectedAccounts =
        Arc::new(Mutex::new(HashMap::<String, Sender<MessageAction>>::new()));
    let storage = Arc::new(Mutex::new(InMemoryAccountRepository::new()));

    let (server_stream, client_stream) = ChannelStream::new_connected_pair();
    let mut connected_client =
        ConnectedClient::new(server_stream, SocketAddr::from_str("127.0.0.1:0").unwrap());
    connected_client.state = CredentialsAuthorization;

    let mut client = Client::new(client_stream);
    client.session = Some(connected_client.session.clone().to_client_session());
    let packet = RequestAuthLoginPacket::new(
        String::from("test"),
        String::from("test"),
        client.session.clone().unwrap().session_id - 1,
    );
    client.send_packet(Box::new(packet)).await.unwrap();

    let error = handle_login_credentials(&mut connected_client, &clients, &storage)
        .await
        .unwrap_err();
    assert_eq!(InvalidData, error.kind());
    assert_eq!("Session mismatch detected.", error.to_string());

    let packet = client.read_packet().await.unwrap();
    let packet = LoginFailPacket::from_decrypted_packet(packet, None).unwrap();
    assert_eq!(AccessFailed, packet.get_reason());
}

#[tokio::test]
async fn it_disconnects_on_invalid_credentials() {
    let clients: ConnectedAccounts =
        Arc::new(Mutex::new(HashMap::<String, Sender<MessageAction>>::new()));
    let storage = Arc::new(Mutex::new(InMemoryAccountRepository::new()));
    {
        storage
            .lock()
            .await
            .save(&Account::new(
                String::from("test"),
                String::from("test"),
                None,
            ))
            .unwrap();
    }

    let (server_stream, client_stream) = ChannelStream::new_connected_pair();
    let mut connected_client =
        ConnectedClient::new(server_stream, SocketAddr::from_str("127.0.0.1:0").unwrap());
    connected_client.state = CredentialsAuthorization;

    let mut client = Client::new(client_stream);
    client.session = Some(connected_client.session.clone().to_client_session());
    let packet = RequestAuthLoginPacket::new(
        String::from("test"),
        String::from("test1"),
        client.session.clone().unwrap().session_id,
    );
    client.send_packet(Box::new(packet)).await.unwrap();

    let error = handle_login_credentials(&mut connected_client, &clients, &storage)
        .await
        .unwrap_err();
    assert_eq!(InvalidData, error.kind());
    assert_eq!("Invalid account credentials.", error.to_string());

    let packet = client.read_packet().await.unwrap();
    let packet = LoginFailPacket::from_decrypted_packet(packet, None).unwrap();
    assert_eq!(UserOrPassWrong, packet.get_reason());
}

#[tokio::test]
async fn it_creates_new_account_if_it_does_not_exist() {
    let clients: ConnectedAccounts =
        Arc::new(Mutex::new(HashMap::<String, Sender<MessageAction>>::new()));
    let storage = Arc::new(Mutex::new(InMemoryAccountRepository::new()));

    let (server_stream, client_stream) = ChannelStream::new_connected_pair();
    let mut connected_client =
        ConnectedClient::new(server_stream, SocketAddr::from_str("127.0.0.1:0").unwrap());
    connected_client.state = CredentialsAuthorization;

    let mut client = Client::new(client_stream);
    client.session = Some(connected_client.session.clone().to_client_session());
    let packet = RequestAuthLoginPacket::new(
        String::from("test"),
        String::from("test"),
        client.session.clone().unwrap().session_id,
    );
    client.send_packet(Box::new(packet)).await.unwrap();

    handle_login_credentials(&mut connected_client, &clients, &storage)
        .await
        .unwrap();

    let packet = client.read_packet().await.unwrap();
    LoginOkPacket::from_decrypted_packet(packet, None).unwrap();

    {
        let lock = storage.lock().await;
        assert_eq!(1, lock.count_all().unwrap())
    }
}

#[tokio::test]
async fn it_logs_in_with_correct_credentials() {
    let clients: ConnectedAccounts =
        Arc::new(Mutex::new(HashMap::<String, Sender<MessageAction>>::new()));
    let storage = Arc::new(Mutex::new(InMemoryAccountRepository::new()));
    {
        storage
            .lock()
            .await
            .save(&Account::new(
                String::from("test"),
                String::from("test"),
                None,
            ))
            .unwrap();
    }

    let (server_stream, client_stream) = ChannelStream::new_connected_pair();

    let mut connected_client =
        ConnectedClient::new(server_stream, SocketAddr::from_str("127.0.0.1:0").unwrap());
    connected_client.state = CredentialsAuthorization;

    let mut client = Client::new(client_stream);
    client.session = Some(connected_client.session.clone().to_client_session());
    let packet = RequestAuthLoginPacket::new(
        String::from("test"),
        String::from("test"),
        client.session.clone().unwrap().session_id,
    );
    client.send_packet(Box::new(packet)).await.unwrap();

    handle_login_credentials(&mut connected_client, &clients, &storage)
        .await
        .unwrap();

    let packet = client.read_packet().await.unwrap();
    LoginOkPacket::from_decrypted_packet(packet, None).unwrap();

    {
        let lock = storage.lock().await;
        assert_eq!(1, lock.count_all().unwrap())
    }
}
