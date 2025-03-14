# server.py
import socket
import threading
import logging
import ssl
import os
import argparse
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("server_logs.log"),
        logging.StreamHandler()
    ]
)

class SecureServer:
    def __init__(self, host='127.0.0.1', port=8443):
        self.host = host
        self.port = port
        self.server_socket = None
        self.clients = []
        self.cert_file = 'server.crt'
        self.key_file = 'server.key'
        
        # Encryption key (32 bytes for AES-256)
        # In a real application, this should be securely stored and distributed
        self.encryption_key = b'SecureConnectionKey12SecureConnect'
        
        # Create SSL context
        self.ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        
        # Check if certificate and key files exist, if not, generate them
        if not (os.path.exists(self.cert_file) and os.path.exists(self.key_file)):
            self.generate_certificates()
            
        self.ssl_context.load_cert_chain(certfile=self.cert_file, keyfile=self.key_file)

    def generate_certificates(self):
        """Generate self-signed certificates for the server"""
        logging.info("Generating self-signed certificates...")
        os.system(f"openssl req -new -newkey rsa:2048 -days 365 -nodes -x509 "
                  f"-subj '/CN=localhost' -keyout {self.key_file} -out {self.cert_file}")
        logging.info("Certificates generated successfully.")

    def encrypt_message(self, plaintext):
        """Encrypt a message using AES-256-CBC"""
        try:
            # Generate a random IV
            iv = os.urandom(16)
            # Create cipher
            cipher = AES.new(self.encryption_key, AES.MODE_CBC, iv)
            # Pad and encrypt
            ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
            # Combine IV and ciphertext and encode to base64 for safe transmission
            encrypted_message = b64encode(iv + ciphertext).decode('utf-8')
            return encrypted_message
        except Exception as e:
            logging.error(f"Encryption error: {e}")
            return None

    def decrypt_message(self, encrypted_message):
        """Decrypt a message using AES-256-CBC"""
        try:
            # Decode from base64
            encrypted_data = b64decode(encrypted_message)
            # Extract IV (first 16 bytes)
            iv = encrypted_data[:16]
            # Extract ciphertext
            ciphertext = encrypted_data[16:]
            # Create cipher
            cipher = AES.new(self.encryption_key, AES.MODE_CBC, iv)
            # Decrypt and unpad
            plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size).decode('utf-8')
            return plaintext
        except Exception as e:
            logging.error(f"Decryption error: {e}")
            return None

    def start(self):
        """Start the server and listen for connections"""
        try:
            # Create socket
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            
            logging.info(f"Server started on {self.host}:{self.port}")
            logging.info("Waiting for connections...")
            
            while True:
                # Accept client connection
                client_socket, client_address = self.server_socket.accept()
                logging.info(f"Connection from {client_address}")
                
                # Wrap the socket with SSL/TLS
                secure_client = self.ssl_context.wrap_socket(client_socket, server_side=True)
                
                # Start a new thread to handle the client
                client_thread = threading.Thread(target=self.handle_client, args=(secure_client, client_address))
                client_thread.daemon = True
                client_thread.start()
                
                self.clients.append((secure_client, client_address))
                
        except KeyboardInterrupt:
            logging.info("Server shutting down...")
        except Exception as e:
            logging.error(f"Error starting server: {e}")
        finally:
            if self.server_socket:
                self.server_socket.close()

    def handle_client(self, client_socket, client_address):
        """Handle client communication"""
        try:
            while True:
                # Receive data from client
                data = client_socket.recv(4096)  # Increased buffer size for encrypted data
                if not data:
                    break
                
                # Decode and decrypt the message
                encrypted_message = data.decode('utf-8')
                message = self.decrypt_message(encrypted_message)
                
                if message:
                    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    logging.info(f"Decrypted message from {client_address}: {message}")
                    
                    # For debugging, also log the encrypted form
                    logging.debug(f"Raw encrypted message: {encrypted_message}")
                    
                    # Send encrypted acknowledgment back to client
                    response = f"Message received at {timestamp}"
                    encrypted_response = self.encrypt_message(response)
                    if encrypted_response:
                        client_socket.send(encrypted_response.encode('utf-8'))
                    else:
                        logging.error("Failed to encrypt response")
                else:
                    logging.error(f"Failed to decrypt message from {client_address}")
                
        except ssl.SSLError as e:
            logging.error(f"SSL Error with client {client_address}: {e}")
        except socket.error as e:
            logging.error(f"Socket error with client {client_address}: {e}")
        except Exception as e:
            logging.error(f"Error handling client {client_address}: {e}")
        finally:
            # Clean up the connection
            client_socket.close()
            if (client_socket, client_address) in self.clients:
                self.clients.remove((client_socket, client_address))
            logging.info(f"Connection with {client_address} closed")

def main():
    parser = argparse.ArgumentParser(description='Secure TCP Server with Encryption')
    parser.add_argument('--host', default='127.0.0.1', help='Server host (default: 127.0.0.1)')
    parser.add_argument('--port', type=int, default=8443, help='Server port (default: 8443)')
    args = parser.parse_args()
    
    server = SecureServer(args.host, args.port)
    server.start()

if __name__ == "__main__":
    main()
