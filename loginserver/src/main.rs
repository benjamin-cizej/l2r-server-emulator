use std::error::Error;

use shared::tokio;
use shared::tokio::net::TcpListener;

use crate::login_server::start_server;

mod login_server;
mod packet;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let listener = TcpListener::bind("127.0.0.1:2106").await?;
    start_server(listener).await?;

    Ok(())
}
