# client.py
import socket
import ssl
import argparse
import sys
import logging
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("client_logs.log"),
        logging.StreamHandler()
    ]
)

class SecureClient:
    def __init__(self, host='127.0.0.1', port=8443):
        self.host = host
        self.port = port
        self.client_socket = None
        self.secure_socket = None
        
        # Encryption key (32 bytes for AES-256)
        # In a real application, this should be securely stored and distributed
        self.encryption_key = b'SecureConnectionKey12SecureConnect'
        
        # Create SSL context
        self.ssl_context = ssl.create_default_context()
        
        # In a production environment, you would verify the server's certificate
        # For this assignment, we'll disable certificate verification
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE

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

    def connect(self):
        """Connect to the server"""
        try:
            # Create socket
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            
            # Wrap with SSL/TLS
            self.secure_socket = self.ssl_context.wrap_socket(self.client_socket, server_hostname=self.host)
            
            # Connect to server
            self.secure_socket.connect((self.host, self.port))
            logging.info(f"Connected to server at {self.host}:{self.port}")
            
            return True
        except socket.error as e:
            logging.error(f"Connection error: {e}")
            return False
        except Exception as e:
            logging.error(f"Error connecting to server: {e}")
            return False

    def send_message(self, message):
        """Send an encrypted message to the server"""
        try:
            # Encrypt the message
            encrypted_message = self.encrypt_message(message)
            if not encrypted_message:
                logging.error("Failed to encrypt message")
                return None
                
            # For debugging
            logging.debug(f"Original message: {message}")
            logging.debug(f"Encrypted message: {encrypted_message}")
            
            # Send the encrypted message
            self.secure_socket.send(encrypted_message.encode('utf-8'))
            
            # Receive the encrypted response
            encrypted_response = self.secure_socket.recv(4096).decode('utf-8')
            
            # Decrypt the response
            response = self.decrypt_message(encrypted_response)
            if response:
                logging.info(f"Decrypted response: {response}")
                return response
            else:
                logging.error("Failed to decrypt server response")
                return None
                
        except ssl.SSLError as e:
            logging.error(f"SSL Error: {e}")
            return None
        except socket.error as e:
            logging.error(f"Socket error: {e}")
            return None
        except Exception as e:
            logging.error(f"Error sending message: {e}")
            return None

    def close(self):
        """Close the connection"""
        if self.secure_socket:
            self.secure_socket.close()
            logging.info("Connection closed")

def main():
    parser = argparse.ArgumentParser(description='Secure TCP Client with Encryption')
    parser.add_argument('--host', default='127.0.0.1', help='Server host (default: 127.0.0.1)')
    parser.add_argument('--port', type=int, default=8443, help='Server port (default: 8443)')
    args = parser.parse_args()
    
    # Import os here for IV generation
    import os
    
    client = SecureClient(args.host, args.port)
    
    if client.connect():
        try:
            while True:
                message = input("Enter message (or 'exit' to quit): ")
                
                if message.lower() == 'exit':
                    break
                
                response = client.send_message(message)
                if response:
                    print(f"Server: {response}")
                else:
                    print("Failed to receive response from server.")
                    break
        except KeyboardInterrupt:
            print("\nExiting...")
        finally:
            client.close()
    else:
        print("Failed to connect to server.")

if __name__ == "__main__":
    main()
