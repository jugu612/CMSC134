from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import base64

def generate_key_pair(filename):
    key = RSA.generate(2048)
    with open(filename, 'wb') as f:
        f.write(key.export_key('PEM'))

def load_key(filename):
    with open(filename, 'rb') as f:
        return RSA.import_key(f.read())

def encrypt_then_sign(message, encryption_key, signing_key):
    cipher = PKCS1_OAEP.new(encryption_key)
    encrypted_message = cipher.encrypt(message.encode())

    signer = pkcs1_15.new(signing_key)
    h = SHA256.new(encrypted_message)
    signature = signer.sign(h)

    return encrypted_message, signature

def verify_then_decrypt(encrypted_message, signature, encryption_key, signing_key):
    verifier = pkcs1_15.new(signing_key)
    h = SHA256.new(encrypted_message)
    try:
        verifier.verify(h, signature)
        cipher = PKCS1_OAEP.new(encryption_key)
        decrypted_message = cipher.decrypt(encrypted_message)
        return decrypted_message.decode()
    except (ValueError, TypeError):
        return "Verification failed!"

def main_menu():
    print("RSA Encryption Program")
    print("1. Generate Key Pairs")
    print("2. Encrypt then Sign")
    print("3. Verify then Decrypt")
    print("4. Exit")
    choice = input("Enter your choice (1/2/3/4): ")
    return choice

if __name__ == "__main__":
    while True:
        choice = main_menu()
        if choice == "1":
            generate_key_pair("encryption_key.pem")
            generate_key_pair("signing_key.pem")
            print("Key pairs generated successfully.")
        elif choice == "2":
            message = input("Enter the message to encrypt and sign: ")
            encryption_key = load_key("encryption_key.pem")
            signing_key = load_key("signing_key.pem")
            encrypted_message, signature = encrypt_then_sign(message, encryption_key, signing_key)
            print("Encrypted and signed message:")
            print("Encrypted message:", base64.b64encode(encrypted_message).decode())
            print("Signature:", base64.b64encode(signature).decode())
            with open("encrypted_message.txt", "w") as file:
                file.write("Encrypted Message:\n")
                file.write(base64.b64encode(encrypted_message).decode() + "\n")
                file.write("Signature:\n")
                file.write(base64.b64encode(signature).decode())
            print("Encrypted message and signature saved to 'encrypted_message.txt'.")
        elif choice == "3":
            encrypted_message = base64.b64decode(input("Enter the encrypted message: ").encode())
            signature = base64.b64decode(input("Enter the signature: ").encode())
            encryption_key = load_key("encryption_key.pem")
            signing_key = load_key("signing_key.pem")
            decrypted_message = verify_then_decrypt(encrypted_message, signature, encryption_key, signing_key)
            print("Decrypted message:", decrypted_message)
        elif choice == "4":
            print("Exiting RSA Encryption Program.")
            break
        else:
            print("Invalid choice. Please enter 1, 2, 3, or 4.")
        
        proceed = input("Do you want to perform another operation? (yes/no): ")
        if proceed.lower() not in ["yes", "y", "ye"]:
            break