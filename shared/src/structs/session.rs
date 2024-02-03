use rand::{thread_rng, Rng};
use rsa::{BigUint, PublicKeyParts, RsaPrivateKey};
use std::net::SocketAddr;

#[derive(Clone)]
pub struct ServerSession {
    pub addr: SocketAddr,
    pub session_id: i32,
    pub blowfish_key: [u8; 16],
    pub rsa_key: RsaPrivateKey,
}

impl ServerSession {
    pub fn new(addr: SocketAddr) -> ServerSession {
        let mut blowfish_key = [0u8; 16];
        thread_rng().fill(&mut blowfish_key[..]);

        ServerSession {
            addr,
            session_id: thread_rng().gen_range(0..0x8000000),
            blowfish_key,
            rsa_key: RsaPrivateKey::new_with_exp(&mut thread_rng(), 1024, &BigUint::from(65537u32))
                .unwrap(),
        }
    }

    pub fn to_client_session(self) -> ClientSession {
        ClientSession {
            addr: self.addr,
            session_id: self.session_id,
            blowfish_key: self.blowfish_key,
            modulus: self.rsa_key.n().to_owned(),
        }
    }
}

pub struct ClientSession {
    pub addr: SocketAddr,
    pub session_id: i32,
    pub blowfish_key: [u8; 16],
    pub modulus: BigUint,
}

impl ClientSession {
    pub fn new(
        addr: SocketAddr,
        session_id: i32,
        blowfish_key: [u8; 16],
        modulus: BigUint,
    ) -> Self {
        ClientSession {
            addr,
            session_id,
            blowfish_key,
            modulus,
        }
    }
}
