from rsa_implementation import rsa_decrypt

if __name__ == "__main__":

    # Retrieve private key
    f = open("files/private_key", "r")
    d = int(f.read())
    f.close()

    f = open("files/public_key", "r")
    public_key = f.readlines()
    n = int(public_key[0])
    e = int(public_key[1]) 
    f.close()

    f = open("files/ctext", "r")
    ciphertext = int(f.read())
    f.close()

    # Decrypt
    recovered_plaintext = rsa_decrypt(ciphertext, d, n)

    print("Here is your message:", recovered_plaintext)