
use crystals_dilithium::dilithium5::{SecretKey as DilithiumSecretKey, Signature, SECRETKEYBYTES};
use kyberlib::{decapsulate, keypair, PublicKey as KyberPublicKey, SecretKey as KyberSecretKey};
use crate::shared::*;

const DIL_SK_PATH: &str = "keys/dil_sk.txt";

pub struct Server{
    dil_sk: DilithiumSecretKey,
    kyb_sk: Option<KyberSecretKey>,
    shared_secret: Option<SharedSecret>,
}

impl Server {
    pub fn new() -> Self{
        Self {
            dil_sk: DilithiumSecretKey::from_bytes(&read_key(DIL_SK_PATH, SECRETKEYBYTES)),
            kyb_sk: None, 
            shared_secret: None,
        }
    }

    pub fn generate_pk_and_sig(&mut self) -> (KyberPublicKey, Signature) {
        let pk = self.generate_kyber_keys();
        (pk, self.sign(&pk))
    }

    pub fn accept_ciphertext(&mut self, ciphertext: CipherText) {
        if let Some(sk) = self.kyb_sk {
            self.shared_secret = Some(decapsulate(&ciphertext, &sk).unwrap());
         } else {
            eprintln!("Failed to decapsulate the ciphertext, because the secret key is missing.");
         }
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

    fn sign(&self, msg: &[u8]) -> Signature {
        self.dil_sk.sign(msg)
    }

    fn generate_kyber_keys(&mut self) -> KyberPublicKey {
        let mut rng = rand::thread_rng();
        let keys = keypair(&mut rng).unwrap();

        self.kyb_sk = Some(keys.secret);
        keys.public
    }
}