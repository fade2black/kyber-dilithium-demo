use kyber_playground::Server;
use kyber_playground::Client;

fn main() {   
    let mut client = Client::new(); 
    let client_messages = ["Hi!", "What's up!", "Me also good!"];
    let mut server =  Server::new();
    let server_messages = ["Hi!", "All good! You?", "Glad to hear from you!"];
    
    // Client initiates a communication.
    // Server accepts the connection and generates a (kyber public key, signature of the public key) pair. 
    let (pk, sig) = server.generate_pk_and_sig();

    // Server sends the public key and signature to the client over a network.
    // Client recieves the payload, verifies the public key, generates
    // a secret key, encapsulates it, and sends it back to the server.
    let ciphertext = client.accept_pk_and_sig(pk, sig);
    // Server recieves the ciphertext and decapsulates it.
    server.accept_ciphertext(ciphertext);
    // At this stage both client and server have a shared secert key
    // and now can securely communicate using one of secert key algorithms.
    // e.g. AES-GCM
    // Server and client start to communicate.
    for i in 0..3 {
        let plaintext = client_messages[i].as_bytes();
        let (nonce, ciphertext) = client.encrypt_message(plaintext);
        // Client sends the nonce and ciphertext over netwwork to the server 
        let decrypted = server.decrypt_message(&ciphertext, nonce);
        println!("Client: {:?}", String::from_utf8(decrypted).unwrap());

        let plaintext = server_messages[i].as_bytes();
        let (nonce, ciphertext) = server.encrypt_message(plaintext);
         // Server replies with the nonce and ciphertext over netwwork to the client
        let decrypted = client.decrypt_message(&ciphertext, nonce);
        println!("Server: {:?}", String::from_utf8(decrypted).unwrap());
    }
                
}
