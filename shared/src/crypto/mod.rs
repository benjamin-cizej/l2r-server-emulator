use crate::network::serverpacket::swap32;
use extcrypto::blowfish::Blowfish;
use extcrypto::symmetriccipher::BlockDecryptor;
use num::ToPrimitive;
use rsa::{PublicKeyParts, RsaPrivateKey};

pub struct Xor {
    enabled: bool,
    secret1: [u8; 16],
    secret2: [u8; 16],
}

impl Xor {
    pub fn new() -> Xor {
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

    pub fn decrypt(&mut self, data: Vec<u8>) -> Vec<u8> {
        if !self.enabled {
            return data;
        }

        let mut ecx = 0;
        let mut decrypted = data.clone();
        for i in 0..data.len() {
            let edx = decrypted[i];
            decrypted[i] = edx ^ self.secret1[i & 0xf] ^ ecx;
            ecx = edx;
        }

        let mut secret = i32::from_le_bytes(self.secret1[8..12].try_into().unwrap());
        secret += decrypted.len().to_i32().unwrap();
        let secret = secret.to_le_bytes();
        for i in 8..12 {
            self.secret1[i] = secret[i - 8];
        }

        decrypted
    }

    pub fn encrypt(&mut self, data: Vec<u8>) -> Vec<u8> {
        if !self.enabled {
            self.enabled = true;
            return data;
        }

        let mut ecx = 0;
        let mut encrypted = data.clone();
        for i in 0..data.len() {
            let edx = encrypted[i];
            ecx ^= edx ^ self.secret2[i & 0xf];
            encrypted[i] = ecx;
        }

        let mut secret = i32::from_le_bytes(self.secret2[8..12].try_into().unwrap());
        secret += encrypted.len().to_i32().unwrap();
        let secret = secret.to_le_bytes();
        for i in 8..12 {
            self.secret2[i] = secret[i - 8];
        }

        encrypted
    }
}

pub trait Scramble {
    fn scramble_modulus(&self) -> Vec<u8>;
}

impl Scramble for RsaPrivateKey {
    fn scramble_modulus(&self) -> Vec<u8> {
        let modulus = self.to_public_key().n().to_bytes_be();
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

pub fn decrypt_packet(packet: Vec<u8>, blowfish: &Blowfish) -> Vec<u8> {
    let mut decrypted_stream: Vec<u8> = vec![];
    for i in packet.chunks(8) {
        let mut dec_buffer = [0u8; 8];
        let mut input = swap32(i);
        blowfish.decrypt_block(&mut input, &mut dec_buffer);
        decrypted_stream.append(&mut Vec::from(swap32(&mut dec_buffer)));
    }

    decrypted_stream
}
