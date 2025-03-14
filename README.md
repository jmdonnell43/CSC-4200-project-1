# CSC-4200-project-1
This project implements a basic client-server model using TCP sockets with both SSL/TLS encryption and AES-256 message encryption in Python 3.

## Features

- TCP server that accepts multiple client connections
- Multi-threaded handling of client requests
- Double-layer security:
  - SSL/TLS encryption for the connection
  - AES-256-CBC encryption for individual messages
- Secure message logging
- Server acknowledgment responses
- Proper error handling for connection and encryption issues

## Requirements

- Python 3.6 or higher
- OpenSSL (for certificate generation)
- PyCryptodome library for AES encryption

## Project Structure

```
├── server.py          # Server implementation
├── client.py          # Client implementation
├── Makefile           # Build and run commands
├── README.md          # This file
└── design_explanation.md  # Design documentation
```

## Installation

1. Clone the repository:
   ```
   git clone <repository-url>
   cd <repository-directory>
   ```

2. Build the project:
   ```
   make build
   ```

This will create a virtual environment and install the required dependencies (PyCryptodome).

## Encryption Details

This implementation uses two layers of encryption:

1. **SSL/TLS Encryption** - Secures the TCP connection itself
2. **AES-256-CBC Encryption** - Encrypts each individual message

The AES encryption process:
- Generates a random Initialization Vector (IV) for each message
- Pads the message to the appropriate block size
- Encrypts the message using AES-256 in CBC mode
- Combines the IV with the ciphertext and encodes to base64 for transmission

This dual-layer approach provides enhanced security for your communication.

## Usage

### Running the Server and Client Together

To run both the server and client:

```
make run
```

This will start the server in the background and launch the client.

### Running the Server Only

```
make run-server
```

### Running the Client Only

```
make run-client
```

### Command Line Arguments

Both the server and client accept the following command line arguments:

- `--host`: Server hostname or IP address (default: 127.0.0.1)
- `--port`: Server port (default: 8443)

Example:
```
python3 server.py --host 0.0.0.0 --port 9000
python3 client.py --host example.com --port 9000
```

### Client Usage

After starting the client, you can send messages to the server:

1. Type your message and press Enter
2. Your message will be encrypted with AES-256 before transmission
3. The server will decrypt your message, process it, and send an encrypted response
4. The client will decrypt and display the server's response
5. Type 'exit' to quit the client

## Cleanup

To remove compiled files, logs, and the virtual environment:

```
make clean
```

## Security Notes

- The encryption key is hardcoded for simplicity. In a real-world application, this should be securely stored and distributed.
- Certificate verification is disabled in the client. In production, proper certificate validation should be implemented.
- The server generates self-signed certificates for SSL/TLS encryption.
