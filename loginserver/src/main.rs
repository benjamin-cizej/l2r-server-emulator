use std::error::Error;

use shared::tokio;

use crate::login_server::start_server;

mod login_server;
mod packet;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    start_server().await?;

    Ok(())
}
