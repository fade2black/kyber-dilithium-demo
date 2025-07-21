
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng, consts::U12, generic_array::GenericArray}, Aes256Gcm
};
pub type Nonce = GenericArray<u8, U12>;

pub type SharedSecret = [u8; 32];
pub type CipherText = [u8; 1088];

use std::fs;

pub fn read_key(path: &str, length: usize) -> Vec<u8>{
    let raw = fs::read_to_string(path).unwrap();
    
    let bytes: Vec<u8> = raw
    .split(',')
    .map(|s| s.trim().parse::<u8>())
    .collect::<Result<_, _>>()
    .unwrap();

    if bytes.len() != length {
        let msg = format!("Invalid key length (expected {}, but got {})", length, bytes.len());

        panic!("{msg}");
    }

    bytes
}

pub fn encrypt_message(plaintext: &[u8], secret: &SharedSecret) -> (Nonce, Vec<u8>) {
    let cipher = Aes256Gcm::new(secret.into());
    let nonce =  Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher.encrypt(&nonce, plaintext.as_ref()).unwrap();
    (nonce, ciphertext)
}

pub fn decrypt_message(ciphertext: &[u8], nonce: Nonce, secret: &SharedSecret) -> Vec<u8> {
    let cipher = Aes256Gcm::new(secret.into());
    let plaintext = cipher.decrypt(&nonce, ciphertext).unwrap();
    plaintext
}