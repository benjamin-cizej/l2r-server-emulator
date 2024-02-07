use loginserver::login_server::start_server;
use loginserver::repository::memory::account::MemoryAccountRepository;
use std::error::Error;

use shared::tokio;
use shared::tokio::net::TcpListener;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let listener = TcpListener::bind("127.0.0.1:2106").await?;
    let storage = MemoryAccountRepository::new();
    start_server(listener, storage).await?;

    Ok(())
}
