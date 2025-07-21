use crystals_dilithium::dilithium5::{PublicKey as DilithiumPublicKey, Signature, PUBLICKEYBYTES};
use kyberlib::{encapsulate, PublicKey as KyberPublicKey};
use crate::shared::*;

const DIL_PK_PATH: &str = "keys/dil_pk.txt";

pub struct Client {
    pk: DilithiumPublicKey,
    shared_secret: Option<SharedSecret>,
}

impl Client {
    pub fn new() -> Self {
        Self {
            pk: DilithiumPublicKey::from_bytes(&read_key(DIL_PK_PATH, PUBLICKEYBYTES)),
            shared_secret: None,
        }
    }

    pub fn verify(&self, sig: Signature, msg: &[u8]) -> bool {
        self.pk.verify(msg, &sig)
    }

    pub fn accept_pk_and_sig(&mut self, pk: KyberPublicKey, sig: Signature) -> CipherText{
        let mut rng = rand::thread_rng();

        // Verify
        if !self.verify(sig, &pk) {
            panic!("Failed to verify the kyber public key.");
        }

        // Encapsulate
        let (ciphertext, shared_secret): (CipherText, SharedSecret) = encapsulate(&pk, &mut rng).unwrap();
        self.shared_secret = Some(shared_secret);

        ciphertext
    }
    
    pub fn encrypt_message(&self, plaintext: &[u8]) -> (Nonce, Vec<u8>) {
        if let Some(ss) = self.shared_secret {
            encrypt_message(plaintext, &ss)
        } else {
             panic!("Failed to encrypt the message, because the secret key is missing.");
        }
    }

    pub fn decrypt_message(&self, ciphertext: &[u8], nonce: Nonce) -> Vec<u8> {
        if let Some(ss) = self.shared_secret {
            decrypt_message(ciphertext, nonce, &ss)
        } else {
            panic!("Failed to descrypt the message, because the secret key is missing.");
         }
    }
}