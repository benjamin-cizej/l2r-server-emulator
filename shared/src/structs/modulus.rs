use rsa::BigUint;

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
    fn scramble_modulus(&self) -> Vec<u8>;

    fn from_scrambled_bytes(bytes: Vec<u8>) -> Self;
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

    fn from_scrambled_bytes(mut bytes: Vec<u8>) -> Self {
        for i in 0..0x40 {
            bytes[0x40 + i] = bytes[0x40 + i] ^ bytes[i];
        }

        for i in 0..4 {
            bytes[0x0d + i] = bytes[0x0d + i] ^ bytes[0x34 + i];
        }

        for i in 0..0x40 {
            bytes[i] = bytes[i] ^ bytes[0x40 + i];
        }

        for i in 0..4 {
            let temp = bytes[i];
            bytes[i] = bytes[0x4d + i];
            bytes[0x4d + i] = temp;
        }

        RsaKeyModulus {
            value: BigUint::from_bytes_be(bytes.as_slice()),
        }
    }
}
