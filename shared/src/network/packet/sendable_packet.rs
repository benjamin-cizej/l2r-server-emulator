use crate::crypto::xor::Xor;
use crate::network::packet::swap32;
use bytes::Buf;
use extcrypto::blowfish::Blowfish;
use extcrypto::symmetriccipher::BlockEncryptor;
use num::ToPrimitive;
use std::io::{Read, Write};

pub struct SendablePacket {
    buffer: Vec<u8>,
}

impl SendablePacket {
    pub fn new() -> SendablePacket {
        SendablePacket { buffer: vec![] }
    }

    pub fn write_uint8(&mut self, number: u8) {
        self.buffer.append(&mut Vec::from(number.to_le_bytes()));
    }

    pub fn write_uint16(&mut self, number: u16) {
        self.buffer.append(&mut Vec::from(number.to_le_bytes()));
    }

    pub fn write_int32(&mut self, number: i32) {
        self.buffer.append(&mut Vec::from(number.to_le_bytes()));
    }

    pub fn write_int64(&mut self, number: i64) {
        self.buffer.append(&mut Vec::from(number.to_le_bytes()));
    }

    pub fn write_double(&mut self, number: f64) {
        self.buffer.append(&mut Vec::from(number.to_le_bytes()));
    }

    pub fn write_bytes(&mut self, mut bytes: Vec<u8>) {
        self.buffer.append(&mut bytes);
    }

    pub fn write_text(&mut self, text: &str) {
        let mut buffer = vec![0u16; text.len()];
        let ucs2 = buffer.as_mut_slice();
        ucs2::encode(text, ucs2).unwrap();

        let mut buffer = vec![0u8; ucs2.len() * 2];
        ucs2.iter()
            .zip(buffer.chunks_exact_mut(2))
            .for_each(|(a, b)| b.copy_from_slice(&a.to_le_bytes()));
        buffer.append(&mut vec![0u8; 2]);

        self.buffer.append(&mut buffer);
    }

    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    pub fn auth_encypher(&mut self) {
        let mut ecx: u64 = 0;
        let bytes = bytes::Bytes::from_iter(self.buffer.clone());
        let buffer_len = bytes.len();
        let mut reader = bytes.reader();
        let mut new_buffer: Vec<u8> = vec![];

        for _i in (0..buffer_len).step_by(4) {
            let mut edx = [0u8; 4];
            match reader.read(&mut edx) {
                Ok(_size) => {
                    ecx = ecx + u32::from_le_bytes(edx) as u64;
                    let edx_int: u32 = u32::from_le_bytes(edx) ^ ecx as u32;
                    new_buffer.write(&edx_int.to_le_bytes()).unwrap();
                }
                Err(_size) => println!("Fail"),
            }
        }

        self.buffer = new_buffer;
    }

    pub fn blowfish_encrypt(&mut self, blowfish: Blowfish) {
        let mut encrypted_stream: Vec<u8> = vec![];
        for i in self.buffer.chunks(8) {
            let mut enc_buffer = [0u8; 8];
            let mut input = swap32(i);
            blowfish.encrypt_block(&mut input, &mut enc_buffer);
            encrypted_stream.append(&mut Vec::from(swap32(&mut enc_buffer)));
        }

        self.buffer = encrypted_stream;
    }

    pub fn pad_bits(&mut self) {
        let size = self.buffer.len().to_i32().unwrap();
        let buffer_size = ((num::integer::div_ceil(size, 4) * 4) - size)
            .to_usize()
            .unwrap();
        let buf: Vec<u8> = vec![0; buffer_size];

        self.buffer = [self.buffer.clone(), buf].concat();
    }

    pub fn add_checksum(&mut self) {
        let size = self.buffer.len();

        let mut checksum: u64 = 0;
        let mut ecx: u32;
        let mut i = 0;

        while i < size - 4 {
            let mut num = [0u8; 4];
            self.buffer.get(i..i + 3).unwrap().copy_to_slice(&mut num);
            ecx = u32::from_le_bytes(num);
            checksum ^= u64::from(ecx);
            i += 4;
        }
        self.write_bytes(checksum.to_le_bytes().to_vec());
    }

    pub fn xor_encrypt(&mut self, xor: &mut Xor) {
        self.buffer = xor.encrypt(self.buffer.clone());
    }

    pub fn to_bytes(self) -> Vec<u8> {
        let length = (self.len() + 2).to_u16().unwrap().to_le_bytes();
        let output = Vec::from([&length, self.buffer.as_slice()].concat());

        output
    }
}

pub type SendablePacketOutput = Box<dyn SendablePacketBytes + Send>;

pub trait SendablePacketBytes {
    fn to_bytes(&self) -> Vec<u8>;
}