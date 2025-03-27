use aes::{cipher::{BlockDecrypt, BlockEncrypt, KeyInit}, Aes256};
use aes::cipher::generic_array::GenericArray;
use openssl::{rsa::{Rsa, Padding}, pkey::{Private, PKey}, hash::MessageDigest, sign::Signer};
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::{TcpListener, TcpStream}};
use std::{error::Error, io::{Read, Write}};
use flate2::{Compression, write::ZlibEncoder, read::ZlibDecoder};
use diesel::{MysqlConnection, r2d2::{Pool, ConnectionManager}};
use dotenvy::dotenv;
use std::sync::Arc;

type DbPool = Pool<ConnectionManager<MysqlConnection>>;

fn establish_connection() -> DbPool {
    let database_url = dotenvy::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let manager = ConnectionManager::<MysqlConnection>::new(database_url);
    Pool::builder()
        .build(manager)
        .expect("Failed to create pool.")
}

fn authenticate_user(pool: &DbPool, username: &str, password: &str) -> Result<bool, Box<dyn Error>> {
    use ssh::models::User;

    let conn = pool.get()?;
    match User::authenticate(conn, username, password) {
        Ok(_) => Ok(true),
        Err(diesel::result::Error::NotFound) => Ok(false),
        Err(err) => Err(Box::new(err)),
    }
}

fn decompress_data(data: &[u8]) -> Vec<u8> {
    let mut decoder = ZlibDecoder::new(data);
    let mut decompressed_data = Vec::new();
    decoder.read_to_end(&mut decompressed_data).expect("Failed to decompress data");
    decompressed_data
}

fn compress_data(data: &[u8]) -> Vec<u8> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data).expect("Failed to compress data");
    encoder.finish().expect("Failed to finish compression")
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    dotenv().ok();
    let pool = Arc::new(establish_connection());

    let listener = TcpListener::bind("127.0.0.1:8080").await?;
    let rsa = Rsa::generate(2048)?;
    println!("Server listening on port 8080...");

    loop {
        let (socket, _) = listener.accept().await?;
        println!("New client connected");
        let rsa_clone = rsa.clone();
        let pool_clone = Arc::clone(&pool);
        tokio::spawn(async move {
            if let Err(e) = handle_client(socket, rsa_clone, pool_clone).await {
                eprintln!("Error handling client: {}", e);
            }
        });
    }
}

fn generate_hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    let pkey = PKey::hmac(key).unwrap();
    let mut signer = Signer::new(MessageDigest::sha256(), &pkey).unwrap();
    signer.update(data).unwrap();
    signer.sign_to_vec().unwrap()
}

fn verify_hmac(key: &[u8], data: &[u8], mac: &[u8]) -> bool {
    let computed_mac = generate_hmac(key, data);
    computed_mac == mac
}

async fn read_message(stream: &mut TcpStream) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut size_buffer = [0u8; 4];
    stream.read_exact(&mut size_buffer).await?;
    let message_size = u32::from_be_bytes(size_buffer) as usize;
    let mut message = vec![0; message_size];
    stream.read_exact(&mut message).await?;
    Ok(message)
}

async fn write_message(stream: &mut TcpStream, message: &[u8]) -> Result<(), Box<dyn Error>> {
    let message_size = (message.len() as u32).to_be_bytes();
    stream.write_all(&message_size).await?;
    stream.write_all(message).await?;
    Ok(())
}

fn aes_encrypt(data: &[u8], key: &[u8; 32]) -> Vec<u8> {
    let cipher = Aes256::new(GenericArray::from_slice(key));
    let padding_len = 16 - (data.len() % 16);
    let mut padded_data = data.to_vec();
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
    decrypted_data
}

async fn execute_command_in_dir(command: &str, dir: &std::path::Path) -> String {
    let output = tokio::process::Command::new("bash")
        .arg("-c")
        .arg(command)
        .current_dir(dir)
        .output()
        .await;

    match output {
        Ok(result) => {
            let stdout = String::from_utf8_lossy(&result.stdout).to_string();
            let stderr = String::from_utf8_lossy(&result.stderr).to_string();
            if !stdout.is_empty() {
                stdout
            } else if !stderr.is_empty() {
                stderr
            } else {
                "No output".to_string()
            }
        },
        Err(e) => format!("Error executing command: {}", e),
    }
}

async fn handle_client(mut stream: TcpStream, rsa: Rsa<Private>, pool: Arc<DbPool>) -> Result<(), Box<dyn Error>> {
    let public_key_pem = rsa.public_key_to_pem()?;
    write_message(&mut stream, &public_key_pem).await?;

    let encrypted_aes_key = read_message(&mut stream).await?;
    let mut decrypted_aes_key = vec![0; rsa.size() as usize];
    rsa.private_decrypt(&encrypted_aes_key, &mut decrypted_aes_key, Padding::PKCS1)?;
    decrypted_aes_key.truncate(32);
    let aes_key: &[u8; 32] = decrypted_aes_key.as_slice().try_into().expect("Failed to convert Vec<u8> to &[u8; 32]");
    let hmac_key = &aes_key[..16];

    let username = String::from_utf8_lossy(&read_message(&mut stream).await?).to_string();
    let password = String::from_utf8_lossy(&read_message(&mut stream).await?).to_string();

    if !authenticate_user(&pool, &username, &password)? {
        let failure_message = "Authentication failed".as_bytes();
        write_message(&mut stream, failure_message).await?;
        eprintln!("Authentication failed for user: {}", username);
        return Ok(());
    } else {
        let success_message = "Authentication successful".as_bytes();
        write_message(&mut stream, success_message).await?;
        println!("Authentication successful for user '{}'", username);
    }

    let mut current_dir = std::env::current_dir()?;

    loop {
        let encrypted_message_with_mac = match read_message(&mut stream).await {
            Ok(message) => message,
            Err(_) => break,
        };

        let (encrypted_message, received_mac) = encrypted_message_with_mac.split_at(encrypted_message_with_mac.len() - 32);

        if !verify_hmac(hmac_key, encrypted_message, received_mac) {
            eprintln!("MAC verification failed.");
            break;
        }

        let decrypted_message = aes_decrypt(encrypted_message, aes_key);
        let decompressed_message = decompress_data(&decrypted_message);
        let command = String::from_utf8_lossy(&decompressed_message).to_string();

        if command == "exit" { break; }

        if command.starts_with("cd") {
            let new_dir = command[3..].trim();
            let new_path = std::path::Path::new(&new_dir);

            let final_path = if new_path.is_absolute() {
                new_path.to_path_buf()
            } else {
                current_dir.join(new_path)
            };

            if final_path.is_dir() {
                current_dir = final_path.to_path_buf();
                let success_message = format!("Changed directory to {}", current_dir.display());
                let compressed_result = compress_data(success_message.as_bytes());
                let encrypted_result = aes_encrypt(&compressed_result, aes_key);
                let mac = generate_hmac(hmac_key, &encrypted_result);
                let mut response_with_mac = encrypted_result.clone();
                response_with_mac.extend_from_slice(&mac);
                write_message(&mut stream, &response_with_mac).await?;
            } else {
                let error_message = format!("No such directory: {}", new_dir);
                let compressed_result = compress_data(error_message.as_bytes());
                let encrypted_result = aes_encrypt(&compressed_result, aes_key);
                let mac = generate_hmac(hmac_key, &encrypted_result);
                let mut response_with_mac = encrypted_result.clone();
                response_with_mac.extend_from_slice(&mac);
                write_message(&mut stream, &response_with_mac).await?;
            }
            continue;
        }

        let command_result = execute_command_in_dir(&command, &current_dir).await;
        let compressed_result = compress_data(command_result.as_bytes());
        let encrypted_result = aes_encrypt(&compressed_result, aes_key);
        let mac = generate_hmac(hmac_key, &encrypted_result);
        let mut response_with_mac = encrypted_result.clone();
        response_with_mac.extend_from_slice(&mac);

        if let Err(e) = write_message(&mut stream, &response_with_mac).await {
            eprintln!("Error sending response: {}", e);
            break;
        }
    }
    Ok(())
}