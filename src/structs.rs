use rand::{thread_rng, Rng};
use rsa::{BigUint, RsaPrivateKey};
use std::net::Ipv4Addr;

pub struct Session {
    pub session_id: u32,
    pub blowfish_key: [u8; 16],
    pub rsa_key: RsaPrivateKey,
}

impl Session {
    pub fn new() -> Session {
        let mut blowfish_key = [0u8; 16];
        thread_rng().fill(&mut blowfish_key[..]);

        Session {
            session_id: thread_rng().gen_range(0..0x8000000),
            blowfish_key,
            rsa_key: RsaPrivateKey::new_with_exp(&mut thread_rng(), 1024, &BigUint::from(65537u32))
                .unwrap(),
        }
    }
}

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
