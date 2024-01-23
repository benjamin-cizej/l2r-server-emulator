use extcrypto::blowfish::Blowfish;

pub trait StaticL2Blowfish {
    fn new_l2_static() -> Blowfish;
}

impl StaticL2Blowfish for Blowfish {
    fn new_l2_static() -> Blowfish {
        Blowfish::new(&[
            0x6b, 0x60, 0xcb, 0x5b, 0x82, 0xce, 0x90, 0xb1, 0xcc, 0x2b, 0x6c, 0x55, 0x6c, 0x6c,
            0x6c, 0x6c,
        ])
    }
}