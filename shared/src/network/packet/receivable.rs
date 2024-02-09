use bytes::buf::Reader;
use bytes::{Buf, Bytes};
use std::fmt::Write;
use std::io::ErrorKind::InvalidData;
use std::io::{Error, ErrorKind, Read, Result};

pub struct ReceivablePacket {
    reader: Reader<Bytes>,
    original_bytes: Vec<u8>,
}

impl ReceivablePacket {
    pub fn new(bytes: Vec<u8>) -> Self {
        ReceivablePacket {
            original_bytes: bytes.clone(),
            reader: Bytes::from(bytes).reader(),
        }
    }

    pub fn to_vec(self) -> Vec<u8> {
        self.reader.into_inner().to_vec()
    }

    fn read_bytes(&mut self, size: usize) -> Result<Vec<u8>> {
        let mut bytes = vec![0u8; size];

        return match self.reader.read(&mut bytes) {
            Ok(_) => Ok(bytes),
            Err(e) => Err(Error::from(e)),
        };
    }

    pub fn read_uint8(&mut self) -> Result<u8> {
        Ok(u8::from_le_bytes(self.read_bytes(1)?.try_into().unwrap()))
    }

    pub fn read_uint16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.read_bytes(2)?.try_into().unwrap()))
    }

    pub fn read_int32(&mut self) -> Result<i32> {
        Ok(i32::from_le_bytes(self.read_bytes(4)?.try_into().unwrap()))
    }

    pub fn read_int64(&mut self) -> Result<i64> {
        Ok(i64::from_le_bytes(self.read_bytes(8)?.try_into().unwrap()))
    }

    pub fn read_double(&mut self) -> Result<f64> {
        Ok(f64::from_le_bytes(self.read_bytes(8)?.try_into().unwrap()))
    }

    pub fn read_raw(&mut self, size: usize) -> Result<Vec<u8>> {
        self.read_bytes(size)
    }

    pub fn read_text(&mut self, size: Option<usize>) -> Result<String> {
        if let Some(size) = size {
            return Ok(String::from_utf8_lossy(&self.read_bytes(size)?)
                .trim_matches(char::from(0))
                .trim()
                .to_string());
        }

        let mut text = String::new();
        loop {
            let num = self.read_uint16()?;
            if num == 0 {
                break;
            }

            text.write_char(char::from_u32(num as u32).unwrap())
                .unwrap();
        }

        Ok(text)
    }

    pub fn verify_checksum(&self) -> Result<()> {
        let size = self.original_bytes.len() - 12;
        if size % 4 != 0 || size <= 4 {
            return Err(Error::from(InvalidData));
        }

        let mut checksum: i64 = 0;
        let count = size - 4;
        let mut check: i64;

        for i in (0..count).step_by(4) {
            let num_bytes = match self.original_bytes.get(i..i + 4) {
                Some(bytes) => bytes,
                None => return Err(Error::from(InvalidData)),
            };
            check = i64::from_le_bytes(num_bytes.try_into().unwrap());
            checksum ^= check;
        }

        let num_bytes = match self.original_bytes.get(count - 4..count - 1) {
            Some(bytes) => bytes,
            None => return Err(Error::from(InvalidData)),
        };

        match checksum == i64::from_le_bytes(num_bytes.try_into().unwrap()) {
            true => Ok(()),
            false => Err(Error::from(ErrorKind::InvalidInput)),
        }
    }
}
