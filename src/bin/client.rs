use aes::cipher::{KeyInit, BlockDecrypt, generic_array::GenericArray, BlockEncrypt};
use aes::Aes256;
use openssl::rsa::{Rsa, Padding};
use openssl::pkey::{PKey, Public};
use rand::Rng;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use std::io::{self, Write, Read};
use std::error::Error;
use openssl::hash::MessageDigest;
use openssl::sign::Signer;
use flate2::{Compression, write::ZlibEncoder, read::ZlibDecoder};

async fn read_rsa(stream: &mut TcpStream) -> Result<Rsa<Public>, Box<dyn Error>> {
    let mut size_buffer = [0u8; 4];
    stream.read_exact(&mut size_buffer).await?;
    let public_key_size = u32::from_be_bytes(size_buffer) as usize;

    let mut public_key_pem = vec![0; public_key_size];
    stream.read_exact(&mut public_key_pem).await?;
    Rsa::public_key_from_pem(&public_key_pem).map_err(|e| e.into())
}

fn compress_data(data: &[u8]) -> Vec<u8> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data).expect("Failed to compress data");
    encoder.finish().expect("Failed to finish compression")
}

fn decompress_data(data: &[u8]) -> Vec<u8> {
    let mut decoder = ZlibDecoder::new(data);
    let mut decompressed_data = Vec::new();
    decoder.read_to_end(&mut decompressed_data).expect("Failed to decompress data");
    decompressed_data
}

async fn send_message(stream: &mut TcpStream, message: &[u8]) -> Result<(), Box<dyn Error>> {
    let message_size = (message.len() as u32).to_be_bytes();
    stream.write_all(&message_size).await?;
    stream.write_all(message).await?;
    Ok(())
}

async fn receive_message(stream: &mut TcpStream) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut size_buffer = [0u8; 4];
    stream.read_exact(&mut size_buffer).await?;
    let message_size = u32::from_be_bytes(size_buffer) as usize;

    let mut message = vec![0; message_size];
    stream.read_exact(&mut message).await?;
    Ok(message)
}

fn generate_aes() -> [u8; 32] {
    let mut rng = rand::thread_rng();
    let mut key = [0u8; 32];
    rng.fill(&mut key);
    key
}

fn rsa_encrypt(data: &[u8], rsa: &Rsa<Public>) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut encrypted_data = vec![0; rsa.size() as usize];
    let encrypted_len = rsa.public_encrypt(data, &mut encrypted_data, Padding::PKCS1)?;
    encrypted_data.truncate(encrypted_len);
    Ok(encrypted_data)
}

fn aes_encrypt(data: &[u8], key: &[u8; 32]) -> Vec<u8> {
    let compressed_data = compress_data(data);
    let cipher = Aes256::new(GenericArray::from_slice(key));
    let padding_len = 16 - (compressed_data.len() % 16);
    let mut padded_data = compressed_data.to_vec();
    padded_data.extend(vec![padding_len as u8; padding_len]);

    let mut encrypted_data = Vec::new();
    for chunk in padded_data.chunks(16) {
        let mut block = GenericArray::clone_from_slice(chunk);
        cipher.encrypt_block(&mut block);
        encrypted_data.extend_from_slice(&block);
    }
    encrypted_data
}

fn aes_decrypt(data: &[u8], key: &[u8; 32]) -> Vec<u8> {
    let cipher = Aes256::new(GenericArray::from_slice(key));
    let mut decrypted_data = Vec::new();

    for chunk in data.chunks(16) {
        let mut block = GenericArray::clone_from_slice(chunk);
        cipher.decrypt_block(&mut block);
        decrypted_data.extend_from_slice(&block);
    }

    let padding_len = *decrypted_data.last().unwrap_or(&0) as usize;
    decrypted_data.truncate(decrypted_data.len() - padding_len);

    decompress_data(&decrypted_data)
}

fn generate_hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    let pkey = PKey::hmac(key).unwrap();
    let mut signer = Signer::new(MessageDigest::sha256(), &pkey).unwrap();
    signer.update(data).unwrap();
    signer.sign_to_vec().unwrap()
}

fn verify_hmac(key: &[u8], data: &[u8], mac: &[u8]) -> bool {
    generate_hmac(key, data) == mac
}

async fn handle_command(mut stream: TcpStream, rsa: Rsa<Public>) -> Result<(), Box<dyn Error>> {
    let aes_key = generate_aes();
    let hmac_key = &aes_key[..16];

    let encrypted_aes_key = rsa_encrypt(&aes_key, &rsa)?;
    send_message(&mut stream, &encrypted_aes_key).await?;

    print!("Enter username: ");
    io::stdout().flush()?;
    let mut username = String::new();
    io::stdin().read_line(&mut username)?;
    let username = username.trim();

    print!("Enter password: ");
    io::stdout().flush()?;
    let mut password = String::new();
    io::stdin().read_line(&mut password)?;
    let password = password.trim();

    send_message(&mut stream, username.as_bytes()).await?;
    send_message(&mut stream, password.as_bytes()).await?;

    let auth_response = match receive_message(&mut stream).await {
        Ok(response) => String::from_utf8_lossy(&response).to_string(),
        Err(e) => {
            eprintln!("Failed to receive authentication response from the server: {}", e);
            return Ok(());
        }
    };

    if auth_response != "Authentication successful" {
        println!("Authentication failed! Closing connection.");
        return Ok(());
    }

    loop {
        print!("Enter command: ");
        io::stdout().flush()?;
        let mut command = String::new();
        io::stdin().read_line(&mut command)?;
        let command = command.trim();

        if command == "exit" {
            break;
        }

        let encrypted_command = aes_encrypt(command.as_bytes(), &aes_key);
        let mac = generate_hmac(hmac_key, &encrypted_command);

        let mut command_with_mac = encrypted_command.clone();
        command_with_mac.extend_from_slice(&mac);

        send_message(&mut stream, &command_with_mac).await?;

        let response_with_mac = match receive_message(&mut stream).await {
            Ok(response) => response,
            Err(e) => {
                eprintln!("Error receiving response: {}", e);
                break;
            }
        };

        let (encrypted_response, received_mac) = response_with_mac.split_at(response_with_mac.len() - 32);

        if !verify_hmac(hmac_key, encrypted_response, received_mac) {
            eprintln!("MAC verification failed. Terminating connection.");
            break;
        }

        let decrypted_response = aes_decrypt(encrypted_response, &aes_key);
        println!("Command output: {}", String::from_utf8_lossy(&decrypted_response));
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let server_address = "127.0.0.1:8080";
    let mut stream = TcpStream::connect(server_address).await?;
    println!("Connected to the server!");

    let rsa = read_rsa(&mut stream).await?;

    handle_command(stream, rsa).await?;

    Ok(())
}
