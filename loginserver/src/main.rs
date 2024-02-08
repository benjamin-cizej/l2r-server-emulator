use loginserver::login_server::start_server;
use loginserver::repository::memory::account::InMemoryAccountRepository;
use std::error::Error;

use shared::tokio;
use shared::tokio::net::TcpListener;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let client_listener = TcpListener::bind("127.0.0.1:2106").await?;
    let gameserver_listener = TcpListener::bind("127.0.0.1:6001").await?;
    let storage = InMemoryAccountRepository::new();
    start_server(client_listener, gameserver_listener, storage).await?;

    Ok(())
}
