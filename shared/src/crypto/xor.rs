use num::ToPrimitive;

pub struct Xor {
    enabled: bool,
    secret1: [u8; 16],
    secret2: [u8; 16],
}

impl Xor {
    pub fn decrypt(&mut self, data: Vec<u8>) -> Vec<u8> {
        if !self.enabled {
            return data;
        }

        let mut ecx = 0;
        let mut decrypted = data.clone();
        for (i, edx) in data.iter().enumerate() {
            decrypted[i] = edx ^ self.secret1[i & 0xf] ^ ecx;
            ecx = *edx;
        }

        let mut secret = i32::from_le_bytes(self.secret1[8..12].try_into().unwrap());
        secret += decrypted.len().to_i32().unwrap();
        let secret = secret.to_le_bytes();
        self.secret1[8..12].copy_from_slice(&secret);

        decrypted
    }

    pub fn encrypt(&mut self, data: Vec<u8>) -> Vec<u8> {
        if !self.enabled {
            self.enabled = true;
            return data;
        }

        let mut ecx = 0;
        let mut encrypted = data.clone();
        for (i, edx) in data.iter().enumerate() {
            ecx ^= edx ^ self.secret2[i & 0xf];
            encrypted[i] = ecx;
        }

        let mut secret = i32::from_le_bytes(self.secret2[8..12].try_into().unwrap());
        secret += encrypted.len().to_i32().unwrap();
        let secret = secret.to_le_bytes();
        self.secret2[8..12].copy_from_slice(&secret);

        encrypted
    }
}

impl Default for Xor {
    fn default() -> Self {
        Xor {
            enabled: false,
            secret1: [
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc8, 0x27, 0x93, 0x01, 0xa1, 0x6c,
                0x31, 0x97,
            ],
            secret2: [
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc8, 0x27, 0x93, 0x01, 0xa1, 0x6c,
                0x31, 0x97,
            ],
        }
    }
}
