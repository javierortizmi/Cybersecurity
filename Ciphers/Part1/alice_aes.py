from cbc_aes_implementation import aes_cbc_encryption
import os


if __name__ == "__main__":
    
    # Plaintext
    plaintext = input("Introduce the message: ")

    # Key
    key = b"This is a 16byte" # password
    f = open("files/key", "wb")
    f.write(key)
    f.close()

    # IV
    iv = os.urandom(16)
    f = open("files/iv", "wb")
    f.write(iv)
    f.close()

    # CBC AES ENCRYPTION 
    ciphertext = aes_cbc_encryption(plaintext, key, iv)
    f = open("files/ctext", "wb")
    f.write(ciphertext)
    f.close()