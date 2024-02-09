use loginserver::packet::gameserver::{
    ConnectFailPacket, FromDecryptedPacket, InitPacket, ServerPacketBytes,
};
use shared::crypto::blowfish::{decrypt_packet, encrypt_packet, StaticL2Blowfish};
use shared::crypto::xor::Xor;
use shared::extcrypto::blowfish::Blowfish;
use shared::network::listener::Acceptable;
use shared::network::packet::pad_bytes;
use shared::network::packet::sendable::SendablePacket;
use shared::network::socket::Socket;
use shared::network::stream::Streamable;
use shared::network::{read_packet, send_packet};
use shared::num::ToPrimitive;
use shared::tokio;
use shared::tokio::time::sleep;
use std::net::SocketAddr;
use std::str::FromStr;
use std::time::Duration;

pub async fn start_server(
    mut client_listener: impl Acceptable,
    mut ls_socket: impl Socket + Send + 'static,
) -> std::io::Result<()> {
    tokio::spawn(async move {
        loop {
            handle_loginserver_connection(&mut ls_socket).await
        }
    });

    loop {
        handle_client_connections(&mut client_listener).await;
    }
}

async fn handle_loginserver_connection(socket: &mut impl Socket) {
    let addr = SocketAddr::from_str("127.0.0.1:6001").unwrap();
    let mut stream = match socket.connect(addr).await {
        Ok(s) => {
            println!("Connected to loginserver");
            s
        }
        Err(e) => {
            println!("Error connecting to login server: {}", e);
            sleep(Duration::from_secs(5)).await;
            return;
        }
    };

    handle_login(&mut stream).await;
}

async fn handle_login(stream: &mut impl Streamable) {
    let blowfish = Blowfish::new_static();
    let mut packet = InitPacket::new("test_auth_key".to_string(), 1, "Bartz".to_string())
        .to_bytes()
        .unwrap();
    pad_bytes(&mut packet);
    encrypt_packet(&mut packet, &blowfish);
    send_packet(stream, packet).await.unwrap();

    let mut packet = read_packet(stream).await.unwrap();
    decrypt_packet(&mut packet, &blowfish);
    if packet[0] == 0x01 {
        let packet = ConnectFailPacket::from_decrypted_packet(packet).unwrap();
        println!("Rejected by login server: {:?}", packet.reason);
        std::process::exit(1);
    }

    loop {
        match read_packet(stream).await {
            Ok(_) => {}
            Err(e) => {
                println!("Disconnected from login server: {}", e);
                break;
            }
        }
    }
}

async fn handle_client_connections(listener: &mut impl Acceptable) {
    let (mut stream, _) = match listener.accept_connection().await {
        Err(e) => {
            println!("Connection could not be established: {:?}", e);
            return;
        }
        Ok((stream, addr)) => (stream, addr),
    };

    tokio::spawn(async move { handle_game_stream(&mut stream).await });
}

async fn handle_game_stream(stream: &mut impl Streamable) {
    let mut xor = Xor::new();
    loop {
        let mut len = [0u8; 2];
        while let Ok(n) = stream.receive_bytes(&mut len).await {
            if n == 0 {
                println!("Connection closed.");
                return;
            }

            let mut data = vec![0; u16::from_le_bytes(len).to_usize().unwrap() - 2];
            stream.receive_bytes(&mut data).await.unwrap_or(0);
            let data = xor.decrypt(data);

            println!("Packet received 0x{:02X?}", data[0]);
            match data[0] {
                0x00 => {
                    let mut packet = SendablePacket::new();
                    packet.write_uint8(0x84);
                    packet.pad_bits();
                    packet.add_checksum();
                    packet.xor_encrypt(&mut xor);

                    stream.send_bytes(packet.to_vec().as_slice()).await.unwrap();
                }
                0x0e => {
                    let mut packet = SendablePacket::new();
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

                    stream.send_bytes(packet.to_vec().as_slice()).await.unwrap();
                }
                0x2b => {
                    let mut packet = SendablePacket::new();
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

                    stream.send_bytes(packet.to_vec().as_slice()).await.unwrap();
                }
                0x12 => {
                    let mut packet = SendablePacket::new();

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

                    stream.send_bytes(packet.to_vec().as_slice()).await.unwrap();

                    let mut packet = SendablePacket::new();
                    packet.write_uint8(0x73);
                    packet.write_uint16(256);

                    packet.pad_bits();
                    packet.add_checksum();
                    packet.xor_encrypt(&mut xor);

                    stream.send_bytes(packet.to_vec().as_slice()).await.unwrap();
                }
                0x11 => {
                    let mut packet = SendablePacket::new();
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

                    stream.send_bytes(packet.to_vec().as_slice()).await.unwrap();

                    let mut packet = SendablePacket::new();
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

                    stream.send_bytes(packet.to_vec().as_slice()).await.unwrap();
                }
                0xd0 => match data[1] {
                    0x2a => {
                        let mut packet = SendablePacket::new();
                        packet.write_uint8(0xFE);
                        packet.write_uint16(0x46);
                        packet.write_int32(2);
                        packet.write_int32(1);
                        packet.write_int32(2);

                        packet.pad_bits();
                        packet.add_checksum();

                        packet.xor_encrypt(&mut xor);

                        stream.send_bytes(packet.to_vec().as_slice()).await.unwrap();
                    }
                    0x58 => {
                        let mut packet = SendablePacket::new();
                        packet.write_uint8(0xFE);
                        packet.write_uint16(0x93);
                        packet.write_int32(0);

                        packet.pad_bits();
                        packet.add_checksum();

                        packet.xor_encrypt(&mut xor);

                        stream.send_bytes(packet.to_vec().as_slice()).await.unwrap();
                    }
                    packet => {
                        println!("Unknown packet received: 0xD0 0x{:02X?}", packet);
                    }
                },
                0x1f => {
                    let mut packet = SendablePacket::new();
                    packet.write_uint8(0xB9);
                    packet.write_int32(1);
                    packet.write_uint16(0);
                    packet.write_int32(0);

                    packet.pad_bits();
                    packet.add_checksum();

                    packet.xor_encrypt(&mut xor);

                    stream.send_bytes(packet.to_vec().as_slice()).await.unwrap();
                }
                0x0f => {
                    let mut packet = SendablePacket::new();
                    let to_x = i32::from_le_bytes(data.get(1..5).unwrap().try_into().unwrap());
                    let to_y = i32::from_le_bytes(data.get(5..9).unwrap().try_into().unwrap());
                    let to_z = i32::from_le_bytes(data.get(9..13).unwrap().try_into().unwrap());

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

                    stream.send_bytes(packet.to_vec().as_slice()).await.unwrap();
                }
                0x57 => {
                    let mut packet = SendablePacket::new();
                    packet.write_uint8(0x71);
                    packet.write_int32(1);

                    packet.pad_bits();
                    packet.add_checksum();

                    packet.xor_encrypt(&mut xor);

                    stream.send_bytes(packet.to_vec().as_slice()).await.unwrap();

                    let mut packet = SendablePacket::new();
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

                    stream.send_bytes(packet.to_vec().as_slice()).await.unwrap();
                }
                0x48 => {
                    let mut packet = SendablePacket::new();
                    packet.write_uint8(0x24);
                    packet.write_int32(1);
                    packet.write_int32(0);
                    packet.write_int32(0);
                    packet.write_int32(0);
                    packet.write_uint8(0);

                    packet.pad_bits();
                    packet.add_checksum();

                    packet.xor_encrypt(&mut xor);

                    stream.send_bytes(packet.to_vec().as_slice()).await.unwrap();
                }
                0x6c => {
                    let mut packet = SendablePacket::new();
                    packet.write_uint8(0xa3);
                    packet.write_int32(1665);
                    packet.write_uint8(0);

                    packet.pad_bits();
                    packet.add_checksum();

                    packet.xor_encrypt(&mut xor);

                    stream.send_bytes(packet.to_vec().as_slice()).await.unwrap();
                }
                packet => {
                    println!("Unknown packet received: 0x{:02X?}", packet);
                }
            }
        }
    }
}
