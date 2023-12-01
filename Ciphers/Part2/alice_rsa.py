from rsa_implementation import rsa_encrypt

if __name__ == "__main__":

    f = open("files/public_key", "r")
    public_key = f.readlines()
    n = int(public_key[0])
    e = int(public_key[1]) 
    f.close()

    plaintext = input("Introduce your message: ")

    # Encrypt
    ciphertext = rsa_encrypt(plaintext, e, n)

    f = open("files/ctext", "w")
    f.write(str(ciphertext))
    f.close()
