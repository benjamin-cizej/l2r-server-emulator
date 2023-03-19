extern crate core;

use crate::network::serverpacket::ServerPacket;
use crate::packet::client::login::RequestAuthLoginPacket;
use crate::packet::client::{decrypt_client_packet, FromDecryptedPacket, LoginClientPacketEnum};
use crate::packet::server::login::{InitPacket, LoginOkPacket, PlayOkPacket, ServerListPacket};
use crate::packet::server::{send_packet, ServerPacketOutput};
use crate::packet::{client, server};
use crate::structs::Server;
use crypto::blowfish::Blowfish;
use num::ToPrimitive;
use rand::{thread_rng, Rng};
use rsa::{BigUint, PublicKeyParts, RsaPrivateKey};
use std::io::ErrorKind;
use std::net::Ipv4Addr;
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    thread, time,
};

mod network;
mod packet;
mod structs;

pub struct Xor {
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

pub struct Session {
    session_id: u32,
    blowfish_key: [u8; 16],
    rsa_key: RsaPrivateKey,
}

impl Session {
    fn new() -> Session {
        let mut blowfish_key = [0u8; 16];
        thread_rng().fill(&mut blowfish_key[..]);

        Session {
            session_id: thread_rng().gen_range(0..0x8000000),
            blowfish_key,
            rsa_key: RsaPrivateKey::new_with_exp(&mut thread_rng(), 1024, &BigUint::from(65537u32))
                .unwrap(),
        }
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

fn main() -> std::io::Result<()> {
    thread::spawn(|| {
        let game_server = TcpListener::bind("127.0.0.1:7778").unwrap();
        for stream in game_server.incoming() {
            match stream {
                Ok(stream) => {
                    println!("Game server connection established");
                    let mut xor = Xor::new();
                    thread::spawn(move || handle_game_stream(stream, &mut xor));
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
                stream.set_nodelay(true).unwrap();
                stream.set_nonblocking(true).unwrap();
                thread::spawn(move || handle_stream(stream.try_clone().unwrap()));
            }
            Err(_) => {}
        }
    }

    Ok(())
}

fn handle_stream(mut stream: TcpStream) {
    let session = Session::new();
    let blowfish = Blowfish::new(&session.blowfish_key);
    send_packet(&mut stream, Box::new(InitPacket::new(&session)));

    'main: loop {
        thread::sleep(time::Duration::from_millis(10));

        loop {
            match decrypt_client_packet(&mut stream, &blowfish) {
                Ok(mut decrypted_packet) => {
                    if let Some(packet_type) = LoginClientPacketEnum::from_packet(&decrypted_packet)
                    {
                        let matched_packet: Box<dyn ServerPacketOutput>;
                        match packet_type {
                            LoginClientPacketEnum::RequestAuthLogin => {
                                RequestAuthLoginPacket::decrypt_credentials(
                                    &mut decrypted_packet,
                                    &session,
                                );
                                let packet =
                                    RequestAuthLoginPacket::from_decrypted_packet(decrypted_packet);
                                println!("Packet: {:?}", packet);

                                matched_packet = Box::new(LoginOkPacket::new(&blowfish));
                            }
                            LoginClientPacketEnum::AuthGameGuard => {
                                let packet =
                                    client::login::AuthGameGuardPacket::from_decrypted_packet(
                                        decrypted_packet,
                                    );
                                let session_id = packet.get_session_id();
                                let mut packet = server::login::AuthGameGuardPacket::new(&blowfish);
                                packet.session_id = session_id;
                                matched_packet = Box::new(packet);
                            }
                            LoginClientPacketEnum::ServerList => {
                                let mut packet = ServerListPacket::new(&blowfish);
                                packet.list.push(Server {
                                    id: 1,
                                    ip: Ipv4Addr::new(127, 0, 0, 1),
                                    port: 7778,
                                    age_limit: false,
                                    pvp_enabled: true,
                                    current_players: 0,
                                    max_players: 100,
                                    status: true,
                                    server_type: 1,
                                    brackets: false,
                                });
                                matched_packet = Box::new(packet)
                            }
                            LoginClientPacketEnum::RequestServerLogin => {
                                matched_packet = Box::new(PlayOkPacket::new(&blowfish));
                            }
                        }

                        send_packet(&mut stream, matched_packet);
                    } else {
                        println!(
                            "Unknown packet received: {:02x?}",
                            decrypted_packet.get(0).unwrap()
                        );
                    }
                }
                Err(e) => match e.kind() {
                    ErrorKind::ConnectionAborted
                    | ErrorKind::UnexpectedEof
                    | ErrorKind::ConnectionReset => {
                        break 'main;
                    }
                    _ => {
                        break;
                    }
                },
            }
        }
    }

    println!("Login server connection terminated");
}

fn handle_game_stream(mut stream: TcpStream, xor: &mut Xor) {
    stream.set_nodelay(true).unwrap();
    stream.set_nonblocking(true).unwrap();

    loop {
        thread::sleep(time::Duration::from_millis(10));

        let mut len = [0u8; 2];
        while stream.peek(&mut len).unwrap_or(0) > 0 {
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
                    packet.xor_encrypt(xor);

                    let mut write = stream.try_clone().unwrap();
                    write.write(packet.prep_output().as_slice()).unwrap();
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

                    packet.xor_encrypt(xor);

                    let mut write = stream.try_clone().unwrap();
                    write.write(packet.prep_output().as_slice()).unwrap();
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

                    packet.xor_encrypt(xor);

                    let mut write = stream.try_clone().unwrap();
                    write.write(packet.prep_output().as_slice()).unwrap();
                    write.flush().unwrap();

                    let mut packet = ServerPacket::new();
                    packet.write_uint8(0x73);
                    packet.write_uint16(256);

                    packet.pad_bits();
                    packet.add_checksum();
                    packet.xor_encrypt(xor);

                    let mut write = stream.try_clone().unwrap();
                    write.write(packet.prep_output().as_slice()).unwrap();
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

                    packet.xor_encrypt(xor);

                    let mut write = stream.try_clone().unwrap();
                    write.write(packet.prep_output().as_slice()).unwrap();
                    write.flush().unwrap();

                    let mut packet = ServerPacket::new();
                    packet.write_uint8(0xFE);
                    packet.write_uint16(0x5F);

                    let mut list: Vec<i32> = vec![0; 75 + 100 + 17];
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

                    packet.xor_encrypt(xor);

                    let mut write = stream.try_clone().unwrap();
                    write.write(packet.prep_output().as_slice()).unwrap();
                    write.flush().unwrap();
                }
                0xd0 => match data[1] {
                    0x2a => {
                        let mut packet = ServerPacket::new();
                        packet.write_uint8(0xFE);
                        packet.write_uint16(0x46);
                        packet.write_int32(2);
                        packet.write_int32(1);
                        packet.write_int32(2);

                        packet.pad_bits();
                        packet.add_checksum();

                        packet.xor_encrypt(xor);

                        let mut write = stream.try_clone().unwrap();
                        write.write(packet.prep_output().as_slice()).unwrap();
                        write.flush().unwrap();
                    }
                    0x58 => {
                        let mut packet = ServerPacket::new();
                        packet.write_uint8(0xFE);
                        packet.write_uint16(0x93);
                        packet.write_int32(0);

                        packet.pad_bits();
                        packet.add_checksum();

                        packet.xor_encrypt(xor);

                        let mut write = stream.try_clone().unwrap();
                        write.write(packet.prep_output().as_slice()).unwrap();
                        write.flush().unwrap();
                    }
                    _ => {}
                },
                0x1f => {
                    let mut packet = ServerPacket::new();
                    packet.write_uint8(0xB9);
                    packet.write_int32(1);
                    packet.write_int32(0);
                    packet.write_int32(0);

                    packet.pad_bits();
                    packet.add_checksum();

                    packet.xor_encrypt(xor);

                    let mut write = stream.try_clone().unwrap();
                    write.write(packet.prep_output().as_slice()).unwrap();
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

                    packet.xor_encrypt(xor);

                    let mut write = stream.try_clone().unwrap();
                    write.write(packet.prep_output().as_slice()).unwrap();
                    write.flush().unwrap();
                }
                packet => {
                    println!("Unknown packet received: 0x{:02X?}", packet);
                }
            }
        }
    }
}
