use rand::{thread_rng, Rng};
use rsa::{BigUint, RsaPrivateKey};

pub struct Session {
    pub session_id: i32,
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
