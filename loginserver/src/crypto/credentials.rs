use shared::network::packet::receivable::ReceivablePacket;
use shared::rand::thread_rng;
use shared::rsa::internals;
use shared::rsa::{BigUint, RsaPrivateKey};
use std::io::ErrorKind::{InvalidData, InvalidInput, Other};
use std::io::{Error, Result};

pub fn encrypt_credentials(
    username: &String,
    password: &String,
    modulus: &BigUint,
) -> Result<[u8; 128]> {
    if username.len() > 14 {
        return Err(Error::new(
            InvalidInput,
            "Username is too long. Maximum of 14 characters is allowed.",
        ));
    }

    if password.len() > 16 {
        return Err(Error::new(
            InvalidInput,
            "Password is too long. Maximum of 16 characters is allowed.",
        ));
    }

    let mut encrypted = vec![0u8; 128];
    encrypted[91] = 36;

    for (i, char) in username.chars().enumerate() {
        encrypted[94 + i] = char as u8;
    }

    for (i, char) in password.chars().enumerate() {
        encrypted[108 + i] = char as u8;
    }

    let e = BigUint::from(65537u32);
    let input = BigUint::from_bytes_be(&encrypted);

    match input.modpow(&e, modulus).to_radix_be(256).try_into() {
        Ok(result) => Ok(result),
        Err(_) => Err(Error::new(Other, "Failed to encrypt credentials.")),
    }
}

pub fn decrypt_credentials(
    bytes: &[u8; 128],
    private_key: &RsaPrivateKey,
) -> Result<(String, String)> {
    let credentials = BigUint::from_bytes_be(bytes);
    return match internals::decrypt(Some(&mut thread_rng()), &private_key, &credentials) {
        Ok(result) => {
            let mut replacement = vec![0u8; 91];
            replacement.append(&mut result.to_bytes_be());
            let mut receivable = ReceivablePacket::new(replacement);
            receivable.read_raw(94).unwrap();
            let username = receivable.read_text(Some(14)).unwrap();
            let password = receivable.read_text(Some(16)).unwrap();
            Ok((username, password))
        }
        Err(e) => Err(Error::new(
            InvalidData,
            format!("Error decryptyng credentials: {}", e.to_string()),
        )),
    };
}
