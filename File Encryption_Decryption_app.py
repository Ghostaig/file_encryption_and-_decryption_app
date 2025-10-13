# file_encrypt_decrypt.py
from cryptography.fernet import Fernet

def generate_key():
    key = Fernet.generate_key()
    with open("secret.key", "wb") as key_file:
        key_file.write(key)

def load_key():
    return open("secret.key", "rb").read()

def encrypt_file(filename):
    key = load_key()
    fernet = Fernet(key)

    with open(filename, "rb") as file:
        data = file.read()

    encrypted = fernet.encrypt(data)
    with open(f"{filename}.enc", "wb") as file:
        file.write(encrypted)

    print(f"✅ Encrypted file saved as {filename}.enc")

def decrypt_file(filename):
    key = load_key()
    fernet = Fernet(key)

    with open(filename, "rb") as file:
        encrypted_data = file.read()

    decrypted = fernet.decrypt(encrypted_data)
    new_filename = filename.replace(".enc", "_decrypted.txt")

    with open(new_filename, "wb") as file:
        file.write(decrypted)

    print(f"✅ Decrypted file saved as {new_filename}")

if __name__ == "__main__":
    choice = input("Do you want to (E)ncrypt or (D)ecrypt? ").lower()
    if choice == "e":
        generate_key()
        file = input("Enter filename to encrypt: ")
        encrypt_file(file)
    elif choice == "d":
        file = input("Enter filename to decrypt: ")
        decrypt_file(file)
    else:
        print("Invalid option.")
