use std::net::Ipv4Addr;

pub struct Server {
    pub id: u8,
    pub ip: Ipv4Addr,
    pub port: i32,
    pub age_limit: bool,
    pub pvp_enabled: bool,
    pub current_players: u16,
    pub max_players: u16,
    pub status: bool,
    pub server_type: i32,
    pub brackets: bool,
}
