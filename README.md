# Async Rust SSH Server 🚀🔐  

A lightweight, asynchronous SSH server implemented in Rust. It uses OpenSSL for RSA key handling and AES encryption to ensure secure communication. Each client is assigned its own working directory, and the server responds to command-line arguments for configuration.  

### ✨ Features  
- **Asynchronous Execution** – Built with async Rust for efficient handling of multiple clients.  
- **Secure Encryption** – Uses RSA (OpenSSL) for authentication and AES for data encryption.  
- **Client Isolation** – Each client gets its own working directory.  
- **Command Handling** – Supports shell commands like `cd`, `pwd`, and more.  
- **Custom Configuration** – Configure server settings via command-line arguments.  
