use rsa::BigUint;

#[derive(Clone)]
pub struct RsaKeyModulus {
    value: BigUint,
}

impl RsaKeyModulus {
    pub fn new(value: BigUint) -> Self {
        RsaKeyModulus { value }
    }

    pub fn to_value(&self) -> BigUint {
        self.value.clone()
    }
}

pub trait Scramble {
    fn to_scrambled_bytes(self) -> Vec<u8>;

    fn from_scrambled_bytes(bytes: Vec<u8>) -> Self;
}

impl Scramble for RsaKeyModulus {
    fn to_scrambled_bytes(self) -> Vec<u8> {
        let modulus = self.value.to_bytes_be();
        let mut scrambled = modulus.clone();
        for i in 0..4 {
            scrambled.swap(i, 77 + i);
        }

        for i in 0..64 {
            scrambled[i] ^= scrambled[64 + i];
        }

        for i in 0..4 {
            scrambled[13 + i] ^= scrambled[52 + i];
        }
        for i in 0..64 {
            scrambled[64 + i] ^= scrambled[i];
        }

        scrambled
    }

    fn from_scrambled_bytes(mut bytes: Vec<u8>) -> Self {
        for i in 0..64 {
            bytes[64 + i] ^= bytes[i];
        }

        for i in 0..4 {
            bytes[13 + i] ^= bytes[52 + i];
        }

        for i in 0..64 {
            bytes[i] ^= bytes[64 + i];
        }

        for i in 0..4 {
            bytes.swap(i, 77 + i);
        }

        RsaKeyModulus {
            value: BigUint::from_bytes_be(bytes.as_slice()),
        }
    }
}
