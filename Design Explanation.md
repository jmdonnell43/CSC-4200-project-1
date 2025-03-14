# Design Explanation Document

This document explains the design choices and implementation details of the TCP Client-Server project with encryption.

## 1. Client-Server Communication Model

Our implementation uses a standard TCP socket-based client-server model with the following characteristics:

### Communication Flow

1. **Server Initialization**:
   - The server creates a TCP socket and binds it to a specified host and port
   - It generates SSL certificates if they don't exist
   - The server listens for incoming connections

2. **Client Connection**:
   - The client creates a TCP socket and wraps it with SSL
   - It connects to the server using the provided host and port
   - Once connected, the client can send encrypted messages to the server

3. **Message Handling**:
   - When a client sends a message, it is first encrypted using AES-256-CBC
   - The server receives the encrypted message, decrypts it, logs it, and sends an encrypted acknowledgment
   - The client decrypts the acknowledgment and displays it to the user
   - The client can continue sending encrypted messages until it terminates the connection

4. **Connection Termination**:
   - The client can terminate the connection by typing 'exit'
   - The server handles unexpected disconnections gracefully

## 2. Threading Model

We implemented a multi-threaded approach to handle multiple clients simultaneously:

### Server Threading

- The main server thread listens for incoming connections
- For each new client connection, a dedicated thread is created using Python's `threading` module
- Each client thread runs the `handle_client` method, which manages the client's communication
- Threads are created as daemon threads to ensure they terminate when the main program exits
- A list of connected clients is maintained for potential broadcast functionality

### Benefits of Multi-threading

- **Concurrency**: Multiple clients can connect and communicate simultaneously
- **Isolation**: Issues with one client don't affect others
- **Simplicity**: Threading is easier to implement than asynchronous approaches for this scale

### Thread Safety Considerations

- Each client connection is handled in its own thread with isolated state
- The shared `clients` list is accessed only by the main thread for adding clients and by individual client threads for removing themselves
- For a production system, proper synchronization would be needed for shared resources

## 3. Encryption Implementation

We implemented a dual-layer encryption approach for maximum security:

### Layer 1: SSL/TLS Encryption (Transport Layer)

- **Certificate Generation**:
  - Self-signed certificates are automatically generated using OpenSSL
  - A 2048-bit RSA key is used for strong encryption
  - Certificates are valid for 365 days

- **SSL Context**:
  - Server creates an SSL context for server authentication
  - Client creates an SSL context but disables certificate verification for simplicity
  - In production, proper certificate verification should be enabled

- **Socket Wrapping**:
  - TCP sockets are wrapped with SSL using the `ssl_context.wrap_socket()` method
  - This ensures the entire connection is encrypted

### Layer 2: AES Encryption (Message Layer)

- **Encryption Process**:
  1. Generate a random 16-byte Initialization Vector (IV) for each message
  2. Create an AES cipher object in CBC mode with the encryption key and IV
  3. Pad the plaintext to ensure it's a multiple of the block size
  4. Encrypt the padded plaintext
  5. Combine the IV with the ciphertext (IV + ciphertext)
  6. Encode to base64 for safe transmission

- **Decryption Process**:
  1. Decode the base64 message
  2. Extract the IV (first 16 bytes)
  3. Extract the ciphertext (remaining bytes)
  4. Create an AES cipher with the same key and extracted IV
  5. Decrypt the ciphertext
  6. Remove padding to get the original message

- **Key Management**:
  - A 32-byte key is used for AES-256 encryption
  - For simplicity, the key is hardcoded in both client and server
  - In a production environment, secure key distribution would be implemented

### Benefits of Dual-Layer Encryption

- **Defense in Depth**: Two independent encryption mechanisms provide additional security
- **Message-Level Security**: Even if the SSL/TLS connection is compromised, individual messages remain encrypted
- **Unique IVs**: Each message has its own random IV, preventing pattern analysis

## 4. Error Handling

Our implementation includes comprehensive error handling for both connection and encryption issues:

### Error Cases Covered

- Connection failures
- SSL/TLS errors
- Socket errors
- Encryption/decryption failures
- Invalid message formats
- Unexpected client disconnections
- General exceptions

### Recovery Mechanisms

- Server continues running even if a client disconnects unexpectedly
- Client provides clear error messages if the server is unreachable
- Encryption failures are logged but don't crash the application
- All errors are logged for debugging purposes

## 5. Logging System

We implemented a detailed logging system with security considerations:

- Logs are stored in both files (`server_logs.log`, `client_logs.log`) and displayed on the console
- Each log entry includes a timestamp, log level, and descriptive message
- Different log levels (INFO, ERROR, DEBUG) are used appropriately
- Encrypted messages are logged at DEBUG level for debugging purposes
- Decrypted messages are logged at INFO level

## 6. Additional Design Considerations

- **Command Line Arguments**: Both client and server accept command-line arguments for host and port
- **Clean Project Structure**: Code is organized into logical classes and functions
- **Makefile Integration**: Simple commands for building, running, and cleaning the project
- **PyCryptodome Library**: Used for reliable cryptographic operations
- **Base64 Encoding**: Ensures encrypted binary data can be safely transmitted as text
- **Graceful Shutdown**: Both client and server handle shutdown signals properly

## Potential Improvements

1. Implement HMAC for message integrity verification
2. Add user authentication with secure password handling
3. Implement proper certificate verification in production
4. Use an asynchronous approach (e.g., asyncio) for even better scalability
5. Add secure key distribution mechanism
6. Implement perfect forward secrecy through key rotation
7. Add support for file transfers with integrity checking
8. Implement connection keep-alive mechanisms
