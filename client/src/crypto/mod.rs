use std::io;
use std::io::ErrorKind::InvalidData;

pub fn dec_xor_pass(raw: &mut [u8], offset: usize, size: usize, key: u32) -> io::Result<()> {
    let stop = 4 + offset;
    let mut pos = match size.checked_sub(12) {
        Some(result) => result,
        None => return Err(io::Error::from(InvalidData)),
    };
    let mut ecx = key;

    while stop <= pos {
        let edx = i32::from_le_bytes([raw[pos], raw[pos + 1], raw[pos + 2], raw[pos + 3]]);
        let edx = (edx as u32) ^ ecx;
        ecx = ecx.wrapping_sub(edx);

        let bytes = edx.to_le_bytes();
        raw[pos] = bytes[0];
        raw[pos + 1] = bytes[1];
        raw[pos + 2] = bytes[2];
        raw[pos + 3] = bytes[3];

        pos -= 4;
    }

    Ok(())
}
