import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from base64 import b64encode, b64decode

# Generate key pairs .pem file
def generate_key_pair(folder, file_prefix):
    print(f"Generating {file_prefix} key pair...")
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    
    # Create "keys" folder if it doesn't exist
    if not os.path.exists(folder):
        os.makedirs(folder)
    
    with open(os.path.join(folder, f"{file_prefix}_private.pem"), 'wb') as f:
        f.write(private_key)
        
    with open(os.path.join(folder, f"{file_prefix}_public.pem"), 'wb') as f:
        f.write(public_key)
    print(f"{file_prefix.capitalize()} key pair generated successfully!")


# Load RSA key file
def load_key(key_file):
    try:
        with open(key_file, 'rb') as f:
            key = RSA.import_key(f.read())
        return key
    except (ValueError, FileNotFoundError) as e:
        print(f"Error loading key from {key_file}: {e}")
        return None

# Encrypt-then-sign, Encrypt(M,Kencryptpbk) Sign(C,Ksignpvk)
def encrypt_sign(message, encryption_public_key_file, signing_private_key_file):
    print("Encrypting message...")
    public_key = load_key(encryption_public_key_file)
    private_key = load_key(signing_private_key_file)
    
    if public_key is None or private_key is None:
        return None, None
    
    cipher = PKCS1_OAEP.new(public_key)
    ciphertext = cipher.encrypt(message.encode())
    
    h = SHA256.new(ciphertext)
    signature = pkcs1_15.new(private_key).sign(h)
    print("Signing the message...")
    print("Message encrypted and signed successfully! Sent!")
    return ciphertext, signature

# Verify-then-decrypt, Verify(S,C,Ksignpbk), Decrypt(C, Kdecryptpvk)
def verify_decrypt(ciphertext, signature, encryption_private_key_file, signing_public_key_file):
    print("Verifying the signature...")
    public_key = load_key(signing_public_key_file)
    private_key = load_key(encryption_private_key_file)
    
    if public_key is None or private_key is None:
        return None
    
    h = SHA256.new(ciphertext)
    try:
        pkcs1_15.new(public_key).verify(h, signature)
        print("Verified.")
        cipher = PKCS1_OAEP.new(private_key)
        message = cipher.decrypt(ciphertext)
        print("Decrypting the text...")
        print("Decrypted message:")
        return message.decode()
    except (ValueError, TypeError) as e:
        print(f"Error verifying signature or decrypting: {e}")
        return None
