use client::Client;
use loginserver::login_server;
use shared::network::channel::channel_connection::ChannelConnector;
use shared::network::channel::channel_listener::ChannelListener;
use shared::network::channel::channel_stream::ChannelStream;
use shared::network::stream::Streamable;
use shared::tokio;
use shared::tokio::net::{TcpListener, TcpStream};

#[tokio::test]
async fn it_connects_with_tcp() {
    let listener = TcpListener::bind("127.0.0.1:2106").await.unwrap();
    tokio::spawn(async move {
        login_server::start_server(listener).await.unwrap();
    });

    let mut client = Client::<TcpStream>::connect_tcp("127.0.0.1:2106").await;
    let mut buffer = [0u8; 2];
    let len = client.connection.receive_bytes(&mut buffer).await.unwrap();
    assert_eq!(2, len);
}

#[tokio::test]
async fn it_connects_with_channel() {
    let mut connector = start_channel_server().await;
    let mut client = Client::<ChannelStream>::connect_channel(&mut connector).await;

    let mut buffer = [0u8; 2];
    let len = client.connection.receive_bytes(&mut buffer).await.unwrap();
    assert_eq!(2, len);
}

#[tokio::test]
async fn it_sends_init_packet_on_connection() {
    let mut connector = start_channel_server().await;
    let mut client = Client::<ChannelStream>::connect_channel(&mut connector).await;
    let packet = client.read_init_packet().await;
    assert_eq!(184, client.get_last_packet_received().len());
    assert_eq!(&50721, packet.get_protocol());
}

async fn start_channel_server() -> ChannelConnector {
    let listener = ChannelListener::new();
    let connector = listener.get_connector();
    tokio::spawn(async move {
        login_server::start_server(listener).await.unwrap();
    });

    connector
}
