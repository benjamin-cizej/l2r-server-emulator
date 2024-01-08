use shared::crypto::Xor;
use shared::network::serverpacket::ServerPacket;
use shared::num::ToPrimitive;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::{thread, time};

fn main() {
    let game_server = TcpListener::bind("127.0.0.1:7778").unwrap();
    for stream in game_server.incoming() {
        if let Ok(stream) = stream {
            println!("Game server connection established");
            stream.set_nodelay(true).unwrap();
            stream.set_nonblocking(true).unwrap();
            thread::spawn(move || handle_game_stream(stream));
        }
    }
}

fn handle_game_stream(mut stream: TcpStream) {
    let mut xor = Xor::new();
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
                    packet.xor_encrypt(&mut xor);

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

                    packet.xor_encrypt(&mut xor);

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

                    packet.xor_encrypt(&mut xor);

                    let mut write = stream.try_clone().unwrap();
                    write.write(packet.prep_output().as_slice()).unwrap();
                    write.flush().unwrap();

                    let mut packet = ServerPacket::new();
                    packet.write_uint8(0x73);
                    packet.write_uint16(256);

                    packet.pad_bits();
                    packet.add_checksum();
                    packet.xor_encrypt(&mut xor);

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

                    packet.xor_encrypt(&mut xor);

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

                    packet.xor_encrypt(&mut xor);

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

                        packet.xor_encrypt(&mut xor);

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

                        packet.xor_encrypt(&mut xor);

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

                    packet.xor_encrypt(&mut xor);

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

                    packet.xor_encrypt(&mut xor);

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
