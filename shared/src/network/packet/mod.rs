use num::ToPrimitive;

pub mod receivable;
pub mod sendable;

pub fn swap32(block: &[u8]) -> [u8; 8] {
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

pub fn prepend_length(packet: &mut Vec<u8>) {
    let length = (packet.len() + 2).to_u16().unwrap().to_le_bytes();

    packet.splice(0..0, length);
}

pub fn pad_bytes(packet: &mut Vec<u8>) {
    let length = packet.len();
    let pad = 8 - (length % 8);
    packet.append(&mut vec![0u8; pad]);
}
