use crate::network::packet::swap32;
use extcrypto::blowfish::Blowfish;
use extcrypto::symmetriccipher::{BlockDecryptor, BlockEncryptor};

pub trait StaticL2Blowfish {
    fn new_static() -> Blowfish;
}

impl StaticL2Blowfish for Blowfish {
    fn new_static() -> Blowfish {
        Blowfish::new(&[
            0x6b, 0x60, 0xcb, 0x5b, 0x82, 0xce, 0x90, 0xb1, 0xcc, 0x2b, 0x6c, 0x55, 0x6c, 0x6c,
            0x6c, 0x6c,
        ])
    }
}

pub fn decrypt_packet(packet: &mut [u8], blowfish: &Blowfish) {
    let mut decrypted_stream: Vec<u8> = vec![];
    for i in packet.chunks(8) {
        let mut dec_buffer = [0u8; 8];
        let input = swap32(i);
        blowfish.decrypt_block(&input, &mut dec_buffer);
        decrypted_stream.append(&mut Vec::from(swap32(&dec_buffer)));
    }

    packet.copy_from_slice(decrypted_stream.as_slice());
}

pub fn encrypt_packet(packet: &mut [u8], blowfish: &Blowfish) {
    let mut encrypted_stream: Vec<u8> = vec![];
    for i in packet.chunks(8) {
        let mut enc_buffer = [0u8; 8];
        let input = swap32(i);
        blowfish.encrypt_block(&input, &mut enc_buffer);
        encrypted_stream.append(&mut Vec::from(swap32(&enc_buffer)));
    }

    packet.copy_from_slice(encrypted_stream.as_slice());
}
