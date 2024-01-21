use rsa::BigUint;

pub struct RsaKeyModulus {
    value: BigUint,
}

impl RsaKeyModulus {
    pub fn new(value: BigUint) -> Self {
        RsaKeyModulus { value }
    }
}

pub trait Scramble {
    fn scramble_modulus(&self) -> Vec<u8>;
}

impl Scramble for RsaKeyModulus {
    fn scramble_modulus(&self) -> Vec<u8> {
        let modulus = self.value.to_bytes_be();
        let mut scrambled = modulus.clone();
        for i in 0..=3 {
            scrambled.swap(i, 0x4d + i);
        }

        for i in 0..0x40 {
            scrambled[i] ^= scrambled[0x40 + i];
        }

        for i in 0..0x04 {
            scrambled[0x0d + i] ^= scrambled[0x34 + i];
        }
        for i in 0..0x40 {
            scrambled[0x40 + i] ^= scrambled[i];
        }

        scrambled
    }
}
