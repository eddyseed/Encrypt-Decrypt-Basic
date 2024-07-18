from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import sys
import os

def encrypt_with_password(text, password):
    salt = b'salt'
    key = PBKDF2(password, salt, dkLen=32, count=1000000)

    cipher = AES.new(key, AES.MODE_ECB)
    padded_text = pad(text.encode(), AES.block_size)
    ciphertext = cipher.encrypt(padded_text)

    return base64.b64encode(ciphertext)

def decrypt_with_password(encrypted_text, password):
    salt = b'salt'
    key = PBKDF2(password, salt, dkLen=32, count=1000000)

    cipher = AES.new(key, AES.MODE_ECB)
    try:
        decrypted_text = cipher.decrypt(base64.b64decode(encrypted_text))
        return unpad(decrypted_text, AES.block_size).decode()
    except ValueError as e:
        if str(e) == "Padding is incorrect.":
            print("Incorrect password.")
            sys.exit(1)
        else:
            raise

def main():
    choice = input("Do you want to encrypt or decrypt? (encrypt/decrypt): ").strip().lower()
    if choice == "encrypt":
        source_choice = input("Do you want to enter the text directly or read from a file? (enter/file): ").strip().lower()
        if source_choice == "enter":
            text = input("Enter the string to encrypt: ")
        elif source_choice == "file":
            file_name = input("Enter the name of the file (in the same directory as the program): ")
            if not os.path.exists(file_name):
                print("File not found.")
                return
            with open(file_name, "r") as file:
                text = file.read()
        else:
            print("Invalid choice.")
            return
        password = input("Enter the password: ")

        encrypted_text = encrypt_with_password(text, password)

        output_choice = input("Do you want to save the encrypted text to a file? (yes/no): ").strip().lower()
        if output_choice == "yes":
            with open("encrypted.txt", "wb") as file:
                file.write(encrypted_text)
            print("Encrypted string has been written to encrypted.txt.")
        elif output_choice == "no":
            print("Encrypted string:", encrypted_text.decode())
        else:
            print("Invalid choice.")
    elif choice == "decrypt":
        source_choice = input("Do you want to enter the encrypted text directly or read from a file? (enter/file): ").strip().lower()
        if source_choice == "enter":
            encrypted_text = input("Enter the encrypted text: ")
        elif source_choice == "file":
            file_name = input("Enter the name of the file (in the same directory as the program): ")
            if not os.path.exists(file_name):
                print("File not found.")
                return
            with open(file_name, "rb") as file:
                encrypted_text = file.read()
        else:
            print("Invalid choice.")
            return
        password = input("Enter the password: ")

        decrypted_text = decrypt_with_password(encrypted_text, password)

        output_choice = input("Do you want to save the decrypted text to a file? (yes/no): ").strip().lower()
        if output_choice == "yes":
            with open("decrypted.txt", "w") as file:
                file.write(decrypted_text)
            print("Decrypted string has been written to decrypted.txt.")
        elif output_choice == "no":
            print("Decrypted string:", decrypted_text)
        else:
            print("Invalid choice.")
    else:
        print("Invalid choice. Please choose 'encrypt' or 'decrypt'.")

if __name__ == "__main__":
    main()
