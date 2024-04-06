from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256


# Generate key pairs .pem file
def generate_key_pair(filename):
    key = RSA.generate(2048)
    with open(filename, 'wb') as f:
        f.write(key.export_key('PEM'))


# Load RSA key file
def load_key(filename):
    try:
        with open(filename, 'rb') as f:
            return RSA.import_key(f.read())
    except (ValueError, FileNotFoundError) as e:
        print("Error loading key:", e)
        return None


# Encrypt-then-sign, Encrypt(M,Kencrypt) Sign(C,Ksign)
def encrypt_then_sign(message, encryption_key, signing_key):
    try:
        # Check if message length exceeds 140 characters
        if len(message) > 140:
            print("Message is too long. Please enter a message with at most 140 characters.")
            return None, None

        # Encrypt
        cipher = PKCS1_OAEP.new(encryption_key)
        ciphertext = cipher.encrypt(message.encode())

        # Hash and sign
        signer = pkcs1_15.new(signing_key)
        h = SHA256.new(ciphertext)
        signature = signer.sign(h)

        return ciphertext, signature
    except ValueError as e:
        print("Encryption error:", e)
        return None, None
    except TypeError as e:
        print("Signing error:", e)
        return None, None


# Verify-then-decrypt, Verify(S,C,Ksign), Decrypt(C, Kdecrypt)
def verify_then_decrypt(ciphertext, signature, encryption_key, signing_key):
    try:
        verifier = pkcs1_15.new(signing_key)
        h = SHA256.new(ciphertext)
        verifier.verify(h, signature)
        cipher = PKCS1_OAEP.new(encryption_key)
        decrypted_message = cipher.decrypt(ciphertext)

        # Check if decrypted message length exceeds 140 characters
        if len(decrypted_message) > 140:
            print("Decrypted message is too long. This might indicate an invalid ciphertext or signature.")
            return None

        return decrypted_message.decode()
    except TypeError as e:
        print("Verification error:", e)
        return None
    except pkcs1_15.VerificationError as e:
        print("Verification failed:", e)
        return None
    except ValueError as e:
        print("Decryption error:", e)
        return None
