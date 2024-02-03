use crate::crypto::xor::Xor;
use bytes::{Buf, Bytes};
use num::ToPrimitive;
use std::io::{BufRead, Read};

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

    pub fn auth_encypher(&mut self, key: i32) {
        let mut ecx = key.clone();
        let mut edx: i32;
        let bytes = Bytes::from(self.buffer.clone());
        let buffer_len = bytes.len();
        let mut reader = bytes.reader();
        let mut pos = 4;
        reader.consume(4);
        while pos < buffer_len - 8 {
            let mut edx_buf = [0u8; 4];
            match reader.read(&mut edx_buf) {
                Ok(_size) => {
                    edx = i32::from_le_bytes(edx_buf);
                    ecx = ecx.wrapping_add(edx);
                    edx ^= ecx;
                    self.buffer[pos..pos + 4].copy_from_slice(&edx.to_le_bytes());
                }
                Err(_size) => println!("Fail"),
            }

            pos += 4;
        }

        self.buffer[pos..pos + 4].copy_from_slice(&ecx.to_le_bytes());
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
            self.buffer.get(i..i + 4).unwrap().copy_to_slice(&mut num);
            ecx = u32::from_le_bytes(num);
            checksum ^= u64::from(ecx);
            i += 4;
        }
        self.write_bytes(checksum.to_le_bytes().to_vec());
    }

    pub fn xor_encrypt(&mut self, xor: &mut Xor) {
        self.buffer = xor.encrypt(self.buffer.clone());
    }

    pub fn to_vec(self) -> Vec<u8> {
        self.buffer
    }
}
