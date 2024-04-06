from base64 import b64encode, b64decode
from rsa_functions import generate_key_pair, encrypt_sign, verify_decrypt
import os

def main_menu():
    print("RSA Encryption Program")
    print("1. Generate Key Pairs")
    print("2. Encrypt then Sign") 
    print("3. Verify then Decrypt")
    print("4. Exit")
    choice = input("Enter your choice (1/2/3/4): ")
    return choice

def main():
    folder = "keys"
    encryption_prefix = "encryption"
    signing_prefix = "signing"
    
    while True:
        choice = main_menu()
        if choice == "1":
            generate_key_pair(folder, encryption_prefix)
            generate_key_pair(folder, signing_prefix)
        elif choice == "2":
            message = input("Enter the message to encrypt and sign: ")
            enc_public_key = os.path.join(folder, f"{encryption_prefix}_public.pem")
            sign_private_key = os.path.join(folder, f"{signing_prefix}_private.pem")
            ciphertext, signature = encrypt_sign(message, enc_public_key, sign_private_key)
            if ciphertext is not None and signature is not None:
                with open("ciphertext.txt", 'wb') as f:
                    f.write(b64encode(ciphertext))
                with open("signature.txt", 'wb') as f:
                    f.write(b64encode(signature))
        elif choice == "3":
            enc_private_key = os.path.join(folder, f"{encryption_prefix}_private.pem")
            sign_public_key = os.path.join(folder, f"{signing_prefix}_public.pem")
            with open("ciphertext.txt", 'rb') as f:
                ciphertext = b64decode(f.read())
            with open("signature.txt", 'rb') as f:
                signature = b64decode(f.read())
            decrypted_message = verify_decrypt(ciphertext, signature, enc_private_key, sign_public_key)
            if decrypted_message:
                print("\033[92m" + decrypted_message + "\033[0m")
            else:
                print("Signature verification failed or decryption error.")
        elif choice == "4":
            print("Exiting program.")
            break
        else:
            print("Invalid choice. Please enter a valid option.")
        
        proceed = input("Do you want to perform another operation? (yes/no): ")
        if proceed.lower() not in ["yes", "y", "ye"]:
            break

if __name__ == "__main__":
    main()