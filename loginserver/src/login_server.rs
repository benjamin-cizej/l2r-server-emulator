use crate::network::handler::client_connection::handle_client_connections;
use crate::network::handler::gameserver_connection::handle_gameserver_connections;
use crate::repository::account::AccountRepository;
use shared::network::listener::Acceptable;
use shared::tokio::select;
use shared::tokio::sync::broadcast::Sender;
use shared::tokio::sync::Mutex;
use std::collections::HashMap;
use std::io::Result;
use std::sync::Arc;

#[derive(Clone, Debug)]
pub enum MessageAction {
    Disconnect,
}

pub type ConnectedAccounts = Arc<Mutex<HashMap<String, Sender<MessageAction>>>>;
pub type ConnectedGameServers = Arc<Mutex<HashMap<u8, String>>>;

pub async fn start_server(
    mut client_listener: impl Acceptable,
    mut gameserver_listener: impl Acceptable,
    repository: impl AccountRepository,
) -> Result<()> {
    let connected_accounts: ConnectedAccounts = Arc::new(Mutex::new(HashMap::new()));
    let connected_gameservers: ConnectedGameServers = Arc::new(Mutex::new(HashMap::new()));
    let repository = Arc::new(Mutex::new(repository));

    select! {
        _ = handle_client_connections(&mut client_listener, &connected_accounts, &repository) => {},
        _ = handle_gameserver_connections(&mut gameserver_listener, &connected_gameservers) => {}
    }

    Ok(())
}
