use shared::tokio::io;
use std::io::ErrorKind::InvalidData;

pub fn xor_encypher_packet(bytes: &mut [u8], key: i32) -> io::Result<()> {
    let mut ecx = key;
    let mut edx: i32;
    let mut pos = 4;
    while pos < bytes.len() - 8 {
        let edx_buf = match bytes.get(pos..pos + 4) {
            None => return Err(std::io::Error::from(InvalidData)),
            Some(data) => data,
        };

        edx = i32::from_le_bytes(edx_buf.try_into().unwrap());
        ecx = ecx.wrapping_add(edx);
        edx ^= ecx;
        bytes[pos..pos + 4].copy_from_slice(&edx.to_le_bytes());

        pos += 4;
    }

    bytes[pos..pos + 4].copy_from_slice(&ecx.to_le_bytes());

    Ok(())
}

pub fn xor_decypher_packet(bytes: &mut [u8]) -> io::Result<()> {
    let size = bytes.len();

    let mut pos = match size.checked_sub(12) {
        Some(result) => result,
        None => return Err(std::io::Error::from(InvalidData)),
    };

    let key = match bytes.get(size - 8..size - 4) {
        Some(key) => i32::from_le_bytes(key.try_into().unwrap()),
        None => return Err(std::io::Error::from(InvalidData)),
    };

    let mut ecx = key;
    let stop = 4;
    while stop <= pos {
        let internal_bytes = match bytes.get(pos..pos + 4) {
            Some(internal) => internal,
            None => return Err(std::io::Error::from(InvalidData)),
        };

        let mut edx = i32::from_le_bytes(internal_bytes.try_into().unwrap());
        edx ^= ecx;
        ecx = ecx.wrapping_sub(edx);

        let edx_bytes = edx.to_le_bytes();
        bytes[pos..pos + 4].copy_from_slice(&edx_bytes);

        pos -= 4;
    }

    Ok(())
}
