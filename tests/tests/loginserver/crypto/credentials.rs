use loginserver::crypto::credentials::{decrypt_credentials, encrypt_credentials};
use shared::rand::thread_rng;
use shared::rsa::{BigUint, PublicKeyParts, RsaPrivateKey};

#[test]
fn it_encrypts_and_decrypts_credentials() {
    let key =
        RsaPrivateKey::new_with_exp(&mut thread_rng(), 1024, &BigUint::from(65537u32)).unwrap();
    let user = String::from("test");
    let pass = String::from("testpass");

    let result = encrypt_credentials(&user, &pass, key.n()).unwrap();
    let (dec_user, dec_pass) = decrypt_credentials(&result, &key).unwrap();

    assert_eq!(user, dec_user);
    assert_eq!(pass, dec_pass);
}

#[test]
fn it_errors_on_encrypting_too_long_credentials() {
    let key =
        RsaPrivateKey::new_with_exp(&mut thread_rng(), 1024, &BigUint::from(65537u32)).unwrap();

    let user = String::from("test123456789012");
    let pass = String::from("testpass12345678");
    encrypt_credentials(&user, &pass, key.n())
        .expect_err("Username is too long. Maximum of 14 characters is allowed.");

    let user = String::from("test1234567890");
    let pass = String::from("testpass123456789");
    encrypt_credentials(&user, &pass, key.n())
        .expect_err("Password is too long. Maximum of 16 characters is allowed.");
}
