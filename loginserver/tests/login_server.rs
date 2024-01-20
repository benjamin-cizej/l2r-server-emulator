use client::Client;
use loginserver::login_server;
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
    let mut buffer = vec![0u8; 2];
    let len = client.connection.receive_bytes(&mut buffer).await.unwrap();
    assert_eq!(2, len);
}

#[tokio::test]
async fn it_connects_with_channel() {
    let listener = ChannelListener::new();
    let mut connector = listener.get_connector();
    tokio::spawn(async move {
        login_server::start_server(listener).await.unwrap();
    });

    let mut client = Client::<ChannelStream>::connect_channel(&mut connector).await;
    let mut buffer = vec![0u8; 2];
    let len = client.connection.receive_bytes(&mut buffer).await.unwrap();
    assert_eq!(2, len);
}
