import base64
import binascii
from rsa_functions import generate_key_pair, load_key, encrypt_then_sign, verify_then_decrypt


def main_menu():
    print("RSA Encryption Program")
    print("1. Generate Key Pairs")
    print("2. Encrypt then Sign")
    print("3. Verify then Decrypt")
    print("4. Exit")
    choice = input("Enter your choice (1/2/3/4): ")
    return choice


def main():
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
            if encryption_key and signing_key:
                ciphertext, signature = encrypt_then_sign(message, encryption_key, signing_key)
                if ciphertext and signature:
                    with open("ciphertext.txt", "w") as file:
                        file.write("Ciphertext:\n")
                        file.write(base64.b64encode(ciphertext).decode() + "\n")
                        file.write("Signature:\n")
                        file.write(base64.b64encode(signature).decode())
                    print("Ciphertext and signature saved to 'ciphertext.txt'.")
        elif choice == "3":
            ciphertext = input("Enter the ciphertext: ")
            try:
                ciphertext = base64.b64decode(ciphertext.encode())
            except binascii.Error as e:
                print("Base64 decoding error:", e)
                continue
                
            signature = input("Enter the signature: ")
            try:
                signature = base64.b64decode(signature.encode())
            except binascii.Error as e:
                print("Base64 decoding error:", e)
                continue
            
            encryption_key = load_key("encryption_key.pem")
            signing_key = load_key("signing_key.pem")
            if encryption_key and signing_key:
                decrypted_message = verify_then_decrypt(ciphertext, signature, encryption_key, signing_key)
                if decrypted_message:
                    print("Decrypted message:", decrypted_message)
        elif choice == "4":
            print("Exiting RSA Encryption Program.")
            break
        else:
            print("Invalid choice. Please enter 1, 2, 3, or 4.")

        proceed = input("Do you want to perform another operation? (yes/no): ")
        if proceed.lower() not in ["yes", "y", "ye"]:
            break


if __name__ == "__main__":
    main()