use std::io;
use std::io::ErrorKind::InvalidData;

pub fn dec_xor_pass(raw: &mut Vec<u8>, offset: usize, size: usize, key: u32) -> io::Result<()> {
    let mut pos = match size.checked_sub(12) {
        Some(result) => result,
        None => return Err(io::Error::from(InvalidData)),
    };

    let mut ecx = key;
    let stop = 4 + offset;
    while stop <= pos {
        let bytes = match raw.get(pos..pos + 4) {
            Some(bytes) => bytes,
            None => return Err(io::Error::from(InvalidData)),
        };
        let edx = i32::from_le_bytes(bytes.try_into().unwrap());
        let edx = (edx as u32) ^ ecx;
        ecx = ecx.wrapping_sub(edx);

        let bytes = edx.to_le_bytes();
        raw[pos..pos + 4].copy_from_slice(&bytes);

        pos -= 4;
    }

    Ok(())
}
