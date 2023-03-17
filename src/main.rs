extern crate core;

use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    thread, time,
};

use ucs2;

use bytes::Buf;
use crypto::{
    blowfish::Blowfish,
    symmetriccipher::{BlockDecryptor, BlockEncryptor},
};
use num::ToPrimitive;
//use rand::Rng;
use rsa::{BigUint, PublicKeyParts, RsaPrivateKey};

struct Xor {
    enabled: bool,
    secret1: [u8; 16],
    secret2: [u8; 16],
}

impl Xor {
    fn new() -> Xor {
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

    fn decrypt(&mut self, data: Vec<u8>) -> Vec<u8> {
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

    fn encrypt(&mut self, data: Vec<u8>) -> Vec<u8> {
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

struct Session {
    blowfish: Blowfish,
    rsa_key: RsaPrivateKey,
}

impl Session {
    fn new() -> Session {
        Session {
            blowfish: Blowfish::new(&[
                0x6bu8, 0x60u8, 0xcbu8, 0x5bu8, 0x82u8, 0xceu8, 0x90u8, 0xb1u8, 0xccu8, 0x2bu8,
                0x6cu8, 0x55u8, 0x6cu8, 0x6cu8, 0x6cu8, 0x6cu8,
            ]),
            rsa_key: RsaPrivateKey::new_with_exp(
                &mut rand::thread_rng(),
                1024,
                &BigUint::from(65537u32),
            )
            .unwrap(),
        }
    }
}

struct ServerPacket {
    buffer: Vec<u8>,
}

impl ServerPacket {
    fn new() -> ServerPacket {
        ServerPacket { buffer: vec![] }
    }

    fn write_uint8(&mut self, number: u8) {
        self.buffer.append(&mut Vec::from(number.to_le_bytes()));
    }

    fn write_uint16(&mut self, number: u16) {
        self.buffer.append(&mut Vec::from(number.to_le_bytes()));
    }

    fn write_int32(&mut self, number: i32) {
        self.buffer.append(&mut Vec::from(number.to_le_bytes()));
    }

    fn write_int64(&mut self, number: i64) {
        self.buffer.append(&mut Vec::from(number.to_le_bytes()));
    }

    fn write_double(&mut self, number: f64) {
        self.buffer.append(&mut Vec::from(number.to_le_bytes()));
    }

    fn write_bytes(&mut self, mut bytes: Vec<u8>) {
        self.buffer.append(&mut bytes);
    }

    fn write_text(&mut self, text: &str) {
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

    fn len(&self) -> usize {
        self.buffer.len()
    }

    fn auth_encypher(&mut self) {
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

    fn blowfish_encrypt(&mut self, blowfish: Blowfish) {
        let mut encrypted_stream: Vec<u8> = vec![];
        for i in self.buffer.chunks(8) {
            let mut enc_buffer = [0u8; 8];
            let mut input = swap32(i);
            blowfish.encrypt_block(&mut input, &mut enc_buffer);
            encrypted_stream.append(&mut Vec::from(swap32(&mut enc_buffer)));
        }

        self.buffer = encrypted_stream;
    }

    fn pad_bits(&mut self) {
        let size = self.buffer.len().to_i32().unwrap();
        let buffer_size = ((num::integer::div_ceil(size, 4) * 4) - size)
            .to_usize()
            .unwrap();
        let buf: Vec<u8> = vec![0; buffer_size];

        self.buffer = [self.buffer.clone(), buf].concat();
    }

    fn add_checksum(&mut self) {
        let size = 4 + (self.len() + 4) % 8;
        let checksum = vec![0; size];
        self.write_bytes(checksum);
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

fn handle_stream(mut stream: TcpStream, session: Session) {
    stream.set_nodelay(true).unwrap();
    stream.set_nonblocking(true).unwrap();

    loop {
        thread::sleep(time::Duration::from_millis(10));

        let mut len = [0u8; 2];
        match stream.peer_addr() {
            Ok(_) => {}
            Err(_) => {
                break;
            }
        }
        match stream.read_exact(&mut len) {
            Ok(_) => {}
            Err(_) => {
                continue;
            }
        };
        let mut data = vec![0; u16::from_le_bytes(len).to_usize().unwrap()];
        stream.read_exact(&mut data).unwrap_err();

        let mut decrypted_stream: Vec<u8> = vec![];
        for i in data.chunks(8) {
            let mut dec_buffer = [0u8; 8];
            let mut input = swap32(i);
            session.blowfish.decrypt_block(&mut input, &mut dec_buffer);
            decrypted_stream.append(&mut Vec::from(swap32(&mut dec_buffer)));
        }

        match decrypted_stream.get(0).unwrap() {
            0x07 => {
                let session_id =
                    i32::from_le_bytes(decrypted_stream.get(1..5).unwrap().try_into().unwrap());
                let mut packet = ServerPacket::new();
                packet.write_uint8(0x0b);
                packet.write_int32(session_id);
                packet.write_int32(0);
                packet.write_int32(0);
                packet.write_int32(0);
                packet.write_int32(0);
                packet.pad_bits();
                packet.add_checksum();
                packet.blowfish_encrypt(session.blowfish);

                let mut write = stream.try_clone().unwrap();
                let length = (packet.len() + 2).to_u16().unwrap().to_le_bytes();
                let output = [&length, packet.buffer.as_slice()].concat();

                write.write(output.as_slice()).unwrap();
                write.flush().unwrap();
            }
            0x00 => {
                let mut packet = ServerPacket::new();
                packet.write_uint8(0x03);
                packet.write_int32(0);
                packet.write_int32(0);
                packet.write_int32(0);
                packet.write_int32(0);
                packet.write_int32(0x000003ea);
                packet.write_int32(0);
                packet.write_int32(0);
                packet.write_int32(0);
                packet.write_bytes(vec![0; 16]);
                packet.pad_bits();
                packet.add_checksum();
                packet.blowfish_encrypt(session.blowfish);

                let mut write = stream.try_clone().unwrap();
                let length = (packet.len() + 2).to_u16().unwrap().to_le_bytes();
                let output = [&length, packet.buffer.as_slice()].concat();

                write.write(output.as_slice()).unwrap();
                write.flush().unwrap();
            }
            0x05 => {
                let mut packet = ServerPacket::new();
                packet.write_uint8(0x04);
                packet.write_uint8(1);
                packet.write_uint8(1);
                packet.write_uint8(1);
                packet.write_uint8(127);
                packet.write_uint8(0);
                packet.write_uint8(0);
                packet.write_uint8(1);
                packet.write_int32(7778);
                packet.write_uint8(0);
                packet.write_uint8(1);
                packet.write_uint16(1);
                packet.write_uint16(100);
                packet.write_uint8(1);
                packet.write_int32(1);
                packet.write_uint8(0);
                packet.write_uint16(0);
                packet.write_uint8(1);
                packet.write_uint8(1);
                packet.write_uint8(1);
                packet.write_uint8(0);
                packet.pad_bits();
                packet.add_checksum();
                packet.blowfish_encrypt(session.blowfish);

                let mut write = stream.try_clone().unwrap();
                let length = (packet.len() + 2).to_u16().unwrap().to_le_bytes();
                let output = [&length, packet.buffer.as_slice()].concat();

                write.write(output.as_slice()).unwrap();
                write.flush().unwrap();
            }
            0x02 => {
                let mut packet = ServerPacket::new();
                packet.write_uint8(0x07);
                packet.write_int32(0);
                packet.write_int32(0);
                packet.pad_bits();
                packet.add_checksum();
                packet.blowfish_encrypt(session.blowfish);

                let mut write = stream.try_clone().unwrap();
                let length = (packet.len() + 2).to_u16().unwrap().to_le_bytes();
                let output = [&length, packet.buffer.as_slice()].concat();

                write.write(output.as_slice()).unwrap();
                write.flush().unwrap();
            }
            packet => {
                println!("Unknown packet received: {:02x?}", packet);
            }
        }

        println!("TEST {:02X?}", decrypted_stream);
    }

    println!("Conn end");
}

fn handle_game_stream(mut stream: TcpStream, mut xor: Xor) {
    stream.set_nodelay(true).unwrap();
    stream.set_nonblocking(true).unwrap();

    loop {
        thread::sleep(time::Duration::from_millis(10));


        match stream.peer_addr() {
            Ok(_) => {}
            Err(_) => {
                break;
            }
        }

        let mut len = [0u8; 2];
        while stream.peek(&mut len).unwrap_or(0) > 0 {
            let mut test = [0u8; 1024];
            let test_len = stream.peek(&mut test).unwrap();

            println!("Stream peek: {:02X?}", test.get(0..test_len).unwrap());
            println!("Stream len: {}", test_len);
            println!("Header size: {}", i16::from_le_bytes(len));

            match stream.read_exact(&mut len) {
                Ok(_) => {}
                Err(_) => {
                    continue;
                }
            };
            let mut data = vec![0; u16::from_le_bytes(len).to_usize().unwrap() - 2];
            stream.read_exact(&mut data).unwrap_or(());
            let data = xor.decrypt(data);

            println!("Packet received {:02X}", data[0]);
            match data[0] {
                0x0e => {
                    let mut packet = ServerPacket::new();
                    packet.write_uint8(0x2e);
                    packet.write_uint8(1);
                    packet.write_bytes(vec![0u8; 8]);
                    packet.write_int32(1);
                    packet.write_int32(1);
                    packet.write_uint8(1);
                    packet.write_int32(0);
                    packet.pad_bits();
                    packet.add_checksum();

                    let encrypted = xor.encrypt(packet.buffer);
                    let mut write = stream.try_clone().unwrap();
                    let length = (encrypted.len() + 2).to_u16().unwrap().to_le_bytes();
                    let output = [&length, encrypted.as_slice()].concat();

                    write.write(output.as_slice()).unwrap();
                    write.flush().unwrap();
                }
                0x2b => {
                    let mut packet = ServerPacket::new();
                    packet.write_uint8(0x09);
                    packet.write_int32(1);
                    packet.write_int32(7);
                    packet.write_uint8(0);
                    packet.write_text("yolo");
                    packet.write_int32(1);
                    packet.write_text("troll");
                    packet.write_int32(0x55555555);
                    packet.write_int32(0);
                    packet.write_int32(0);
                    packet.write_int32(0);
                    packet.write_int32(1);
                    packet.write_int32(18);
                    packet.write_int32(1);
                    packet.write_int32(45478);
                    packet.write_int32(48916);
                    packet.write_int32(-3086);
                    packet.write_double(96.0);
                    packet.write_double(50.0);
                    packet.write_int32(0);
                    packet.write_int64(0);
                    packet.write_double(0.0);
                    packet.write_int32(1);
                    packet.write_int32(0);
                    packet.write_int32(0);
                    packet.write_int32(0);

                    for _i in 0..7 {
                        packet.write_int32(0);
                    }

                    for _i in 0..26 {
                        packet.write_int32(0);
                    }

                    packet.write_int32(0);
                    packet.write_int32(0);
                    packet.write_int32(0);

                    packet.write_double(96.0);
                    packet.write_double(50.0);
                    packet.write_int32(0);
                    packet.write_int32(18);
                    packet.write_int32(1);
                    packet.write_uint8(127);
                    packet.write_int32(0);
                    packet.write_int32(0);
                    packet.write_int32(0);
                    packet.write_int32(0);
                    packet.write_int32(0);
                    packet.write_int32(0);

                    packet.write_double(0.0);
                    packet.write_double(0.0);

                    packet.write_int32(20000);

                    packet.pad_bits();
                    packet.add_checksum();

                    let encrypted = xor.encrypt(packet.buffer);
                    let mut write = stream.try_clone().unwrap();
                    let length = (encrypted.len() + 2).to_u16().unwrap().to_le_bytes();
                    let output = [&length, encrypted.as_slice()].concat();

                    write.write(output.as_slice()).unwrap();
                    write.flush().unwrap();
                }
                0x12 => {
                    let mut packet = ServerPacket::new();

                    packet.write_uint8(0x0b);
                    packet.write_text("yolo");
                    packet.write_int32(1);
                    packet.write_text("test");
                    packet.write_int32(0x55555555);
                    packet.write_int32(0);
                    packet.write_int32(0);
                    packet.write_int32(0);
                    packet.write_int32(1);
                    packet.write_int32(18);
                    packet.write_int32(1);
                    packet.write_int32(45478);
                    packet.write_int32(48916);
                    packet.write_int32(0);
                    packet.write_double(96.0);
                    packet.write_double(59.0);
                    packet.write_int32(0);
                    packet.write_int32(0);
                    packet.write_int32(0);
                    packet.write_int32(1);
                    packet.write_int32(0);
                    packet.write_int32(0);
                    packet.write_int32(37);
                    packet.write_int32(21);
                    packet.write_int32(25);
                    packet.write_int32(40);
                    packet.write_int32(24);
                    packet.write_int32(23);
                    packet.write_int32(960);
                    packet.write_int32(0);
                    packet.write_int32(0x12);
                    packet.write_int32(0);
                    packet.write_int32(0);
                    packet.write_int32(0);
                    packet.write_int32(0);
                    packet.write_bytes(vec![0; 64]);
                    packet.write_int32(0);

                    packet.pad_bits();
                    packet.add_checksum();

                    let encrypted = xor.encrypt(packet.buffer);
                    let mut write = stream.try_clone().unwrap();
                    let length = (encrypted.len() + 2).to_u16().unwrap().to_le_bytes();
                    let output = [&length, encrypted.as_slice()].concat();

                    write.write(output.as_slice()).unwrap();
                    write.flush().unwrap();


                    let mut packet = ServerPacket::new();
                    packet.write_uint8(0x73);
                    packet.write_uint16(256);

                    packet.pad_bits();
                    packet.add_checksum();
                    let encrypted = xor.encrypt(packet.buffer);
                    let mut write = stream.try_clone().unwrap();
                    let length = (encrypted.len() + 2).to_u16().unwrap().to_le_bytes();
                    let output = [&length, encrypted.as_slice()].concat();

                    write.write(output.as_slice()).unwrap();
                    write.flush().unwrap();
                }
                0x11 => {
                    let mut packet = ServerPacket::new();
                    packet.write_uint8(0x32);
                    packet.write_int32(45478);
                    packet.write_int32(48916);
                    packet.write_int32(-3086);

                    packet.write_int32(0);
                    packet.write_int32(1);
                    packet.write_text("yolo");
                    packet.write_int32(1);
                    packet.write_int32(0);

                    packet.write_int32(18);
                    packet.write_int32(1);
                    packet.write_int32(0);
                    packet.write_int32(0);
                    packet.write_double(0.0);
                    packet.write_int32(21);
                    packet.write_int32(24);
                    packet.write_int32(25);
                    packet.write_int32(37);
                    packet.write_int32(23);
                    packet.write_int32(40);
                    packet.write_int32(96);
                    packet.write_int32(96);
                    packet.write_int32(59);
                    packet.write_int32(59);
                    packet.write_int32(0);
                    packet.write_int32(0);
                    packet.write_int32(50000);
                    packet.write_int32(20);

                    for _i in 0..78 {
                        packet.write_int32(0);
                    }

                    packet.write_int32(0);
                    packet.write_int32(0);
                    packet.write_int32(2);
                    packet.write_int32(312);
                    packet.write_int32(48);
                    packet.write_int32(30);
                    packet.write_int32(30);
                    packet.write_int32(41);
                    packet.write_int32(6);
                    packet.write_int32(386);
                    packet.write_int32(312);
                    packet.write_int32(54);
                    packet.write_int32(0);
                    packet.write_int32(0);
                    packet.write_int32(129);
                    packet.write_int32(85);
                    packet.write_int32(129);
                    packet.write_int32(85);
                    packet.write_int32(0);
                    packet.write_int32(0);
                    packet.write_int32(0);
                    packet.write_int32(0);
                    packet.write_double(8.0);
                    packet.write_double(1.1);
                    packet.write_double(7.5);
                    packet.write_double(24.0);
                    packet.write_int32(0);
                    packet.write_int32(0);
                    packet.write_int32(0);
                    packet.write_int32(1);
                    packet.write_text("test");
                    packet.write_int32(0);
                    packet.write_int32(0);
                    packet.write_int32(0);
                    packet.write_int32(0);
                    packet.write_int32(0);
                    packet.write_uint8(0);
                    packet.write_uint8(0);
                    packet.write_uint8(0);
                    packet.write_int32(0);
                    packet.write_int32(0);

                    packet.write_uint16(0);
                    packet.write_uint8(0);
                    packet.write_int32(0);
                    packet.write_uint8(0);
                    packet.write_int32(0);

                    packet.write_uint16(20);
                    packet.write_uint16(0);

                    packet.write_int32(0);
                    packet.write_uint16(60);
                    packet.write_int32(18);
                    packet.write_int32(0);
                    packet.write_int32(50);
                    packet.write_int32(50);
                    packet.write_uint8(0);
                    packet.write_uint8(0);
                    packet.write_int32(0);
                    packet.write_uint8(0);
                    packet.write_uint8(1);
                    packet.write_uint8(0);

                    packet.write_int32(0);
                    packet.write_int32(0);
                    packet.write_int32(0);
                    packet.write_int32(0xffffff);
                    packet.write_uint8(1);

                    packet.write_int32(0);
                    packet.write_int32(0);
                    packet.write_int32(0x1539E0);
                    packet.write_int32(0);
                    packet.write_int32(0);

                    packet.write_uint16(0);
                    packet.write_uint16(0);
                    packet.write_uint16(0);
                    packet.write_uint16(0);
                    packet.write_uint16(0);
                    packet.write_uint16(0);
                    packet.write_uint16(0);
                    packet.write_uint16(0);

                    packet.write_int32(0);
                    packet.write_int32(0);
                    packet.write_int32(1);
                    packet.write_int32(20000);
                    packet.write_int32(0);

                    packet.pad_bits();
                    packet.add_checksum();

                    let encrypted = xor.encrypt(packet.buffer);
                    let mut write = stream.try_clone().unwrap();
                    let length = (encrypted.len() + 2).to_u16().unwrap().to_le_bytes();
                    let output = [&length, encrypted.as_slice()].concat();

                    write.write(output.as_slice()).unwrap();
                    write.flush().unwrap();


                    let mut packet = ServerPacket::new();
                    packet.write_uint8(0xFE);

                    let mut list: Vec<i32> = vec![0; 75+100+17];
                    for i in 0..=74 {
                        list[i] = i.to_i32().unwrap();
                    }

                    for i in 0..=99 {
                        list[74 + i] = 1000 + i.to_i32().unwrap();
                    }

                    for i in 0..16 {
                        list[74 + 99 + i] = 5000 + i.to_i32().unwrap();
                    }

                    packet.write_int32(list.len().to_i32().unwrap());

                    for action in list {
                        packet.write_int32(action);
                    }


                    packet.pad_bits();
                    packet.add_checksum();

                    let encrypted = xor.encrypt(packet.buffer);
                    let mut write = stream.try_clone().unwrap();
                    let length = (encrypted.len() + 2).to_u16().unwrap().to_le_bytes();
                    let output = [&length, encrypted.as_slice()].concat();

                    write.write(output.as_slice()).unwrap();
                    write.flush().unwrap();
                }
                0xd0 => {
                    match data[1] {
                        0x2a => {
                            let mut packet = ServerPacket::new();
                            packet.write_uint8(0xFE);
                            packet.write_uint16(0x46);
                            packet.write_int32(2);
                            packet.write_int32(1);
                            packet.write_int32(2);

                            packet.pad_bits();
                            packet.add_checksum();

                            let encrypted = xor.encrypt(packet.buffer);
                            let mut write = stream.try_clone().unwrap();
                            let length = (encrypted.len() + 2).to_u16().unwrap().to_le_bytes();
                            let output = [&length, encrypted.as_slice()].concat();

                            write.write(output.as_slice()).unwrap();
                            write.flush().unwrap();
                        },
                        0x58 => {
                            let mut packet = ServerPacket::new();
                            packet.write_uint8(0xFE);
                            packet.write_uint16(0x93);
                            packet.write_int32(0);

                            packet.pad_bits();
                            packet.add_checksum();

                            let encrypted = xor.encrypt(packet.buffer);
                            let mut write = stream.try_clone().unwrap();
                            let length = (encrypted.len() + 2).to_u16().unwrap().to_le_bytes();
                            let output = [&length, encrypted.as_slice()].concat();

                            write.write(output.as_slice()).unwrap();
                            write.flush().unwrap();
                        }
                        _ => {}
                    }
                }
                0x1f => {
                    let mut packet = ServerPacket::new();
                    packet.write_uint8(0xB9);
                    packet.write_int32(1);
                    packet.write_int32(0);
                    packet.write_int32(0);

                    packet.pad_bits();
                    packet.add_checksum();

                    let encrypted = xor.encrypt(packet.buffer);
                    let mut write = stream.try_clone().unwrap();
                    let length = (encrypted.len() + 2).to_u16().unwrap().to_le_bytes();
                    let output = [&length, encrypted.as_slice()].concat();

                    write.write(output.as_slice()).unwrap();
                    write.flush().unwrap();
                }
                0x0f => {
                    let mut packet = ServerPacket::new();
                    let to_x = i32::from_le_bytes(data.get(1..5).unwrap().try_into().unwrap());
                    let to_y = i32::from_le_bytes(data.get(5..9).unwrap().try_into().unwrap());
                    let to_z = i32::from_le_bytes(data.get(9..13).unwrap().try_into().unwrap());

                    println!("X {:02X?}", data.get(1..5).unwrap());
                    println!("TO {} {} {}", to_x, to_y, to_z);

                    let from_x = i32::from_le_bytes(data.get(13..17).unwrap().try_into().unwrap());
                    let from_y = i32::from_le_bytes(data.get(17..21).unwrap().try_into().unwrap());
                    let from_z = i32::from_le_bytes(data.get(21..25).unwrap().try_into().unwrap());

                    packet.write_uint8(0x2f);
                    packet.write_int32(1);
                    packet.write_int32(to_x);
                    packet.write_int32(to_y);
                    packet.write_int32(to_z);

                    packet.write_int32(from_x);
                    packet.write_int32(from_y);
                    packet.write_int32(from_z);

                    packet.pad_bits();
                    packet.add_checksum();

                    let encrypted = xor.encrypt(packet.buffer);
                    let mut write = stream.try_clone().unwrap();
                    let length = (encrypted.len() + 2).to_u16().unwrap().to_le_bytes();
                    let output = [&length, encrypted.as_slice()].concat();

                    write.write(output.as_slice()).unwrap();
                    write.flush().unwrap();
                }
                packet => {
                    println!("Unknown packet received: 0x{:02X?}", packet);
                }
            }
        }

    }
}

fn main() -> std::io::Result<()> {
    thread::spawn(|| {
        let game_server = TcpListener::bind("127.0.0.1:7778").unwrap();
        for stream in game_server.incoming() {
            match stream {
                Ok(stream) => {
                    println!("Game server connection established");
                    let xor = Xor::new();
                    thread::spawn(move || handle_game_stream(stream, xor));
                }
                Err(_) => {}
            }
        }
    });

    let login_server = TcpListener::bind("127.0.0.1:2106")?;
    for stream in login_server.incoming() {
        match stream {
            Ok(stream) => {
                println!("Login server connection established");

                let session = Session::new();
                let mut packet = ServerPacket::new();
                packet.write_uint8(0);
                packet.write_int32(1234);
                packet.write_int32(0xc621i32);
                packet.write_bytes(session.rsa_key.scramble_modulus());
                packet.write_int32(0);
                packet.write_int32(0);
                packet.write_int32(0);
                packet.write_int32(0);
                packet.write_bytes(Vec::from([
                    0x6bu8, 0x60u8, 0xcbu8, 0x5bu8, 0x82u8, 0xceu8, 0x90u8, 0xb1u8, 0xccu8, 0x2bu8,
                    0x6cu8, 0x55u8, 0x6cu8, 0x6cu8, 0x6cu8, 0x6cu8,
                ]));
                packet.write_uint8(0);
                packet.write_bytes(Vec::from([0u8; 14]));

                packet.auth_encypher();
                packet.pad_bits();

                packet.blowfish_encrypt(session.blowfish);

                let length = (packet.len() + 2).to_u16().unwrap().to_le_bytes();
                let output = [&length, packet.buffer.as_slice()].concat();

                let mut write = stream.try_clone().unwrap();
                thread::spawn(move || handle_stream(stream.try_clone().unwrap(), session));

                write.write(output.as_slice()).unwrap();
                write.flush().unwrap();
            }
            Err(_) => {}
        }
    }

    Ok(())
}

fn swap32(block: &[u8]) -> [u8; 8] {
    let mut output = [0u8; 8];
    let mut iteration = 1;
    for i in block.chunks(4) {
        let mut counter = iteration * 4;

        for j in i {
            output[counter - 1] = j.clone();
            counter -= 1;
        }

        iteration += 1;
    }

    output
}
