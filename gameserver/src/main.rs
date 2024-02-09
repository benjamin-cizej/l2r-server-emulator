use gameserver::gameserver::start_server;
use shared::tokio;
use shared::tokio::net::{TcpListener, TcpSocket};
use std::io;

#[tokio::main]
async fn main() -> io::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:7778").await?;
    let login_stream = TcpSocket::new_v4()?;
    start_server(listener, login_stream).await?;
    Ok(())
}
