from cbc_aes_implementation import aes_cbc_decryption


if __name__ == "__main__":
    
    # Ciphertext
    f = open("files/ctext", "rb")
    ciphertext = f.read()
    f.close()
    
    # IV
    f = open("files/iv", "rb")
    iv = f.read()
    f.close()
    
    # Key
    f = open("files/key", "rb")
    key = f.read()
    f.close()
    
    # CBC AES DECRYPTION 
    recovered_plaintext = aes_cbc_decryption(ciphertext, key, iv)
    
    # Print plaintext to terminal
    print("You have a new message:", recovered_plaintext)