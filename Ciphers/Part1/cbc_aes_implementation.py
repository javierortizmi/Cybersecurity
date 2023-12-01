from aes_implementation import aes_encryption, aes_decryption, xor_bytes

AES_BLOCK_SIZE = 16


def add_padding(plain: str) -> bytes:
    if len(plain) % AES_BLOCK_SIZE != 0:
        # Add padding by adding '0' 
        plain += "0" * (AES_BLOCK_SIZE - len(plain) % AES_BLOCK_SIZE)
        return plain.encode()

def aes_cbc_encryption(plain: str, key: bytes, iv: bytes) -> bytes:

    plain = add_padding(plain)

    cipher = []

    p_1 = plain[:AES_BLOCK_SIZE]                    # First block of plaintext
    c_1 = aes_encryption(xor_bytes(p_1, iv), key)   # First block of ciphertext (initialized with iv)
    cipher += c_1

    c_j_1 = c_1
    for j in range(1, len(plain) // AES_BLOCK_SIZE):
        p_j = plain[j * AES_BLOCK_SIZE : (j + 1) * AES_BLOCK_SIZE]
        c_j = aes_encryption(xor_bytes(p_j, c_j_1), key)
        cipher += c_j
        c_j_1 = c_j

    return bytes(cipher)

def remove_padding(plain: bytes) -> str:
    return plain.decode().strip("0")

def aes_cbc_decryption(cipher: bytes, key: bytes, iv: bytes) -> bytes:
    plain = []

    c_1 = cipher[:AES_BLOCK_SIZE]
    o_1 = aes_decryption(c_1, key)
    p_1 = xor_bytes(o_1, iv)
    plain += p_1

    c_j_1 = c_1
    for j in range(1, len(cipher) // AES_BLOCK_SIZE):
        c_j = cipher[j * AES_BLOCK_SIZE : (j + 1) * AES_BLOCK_SIZE]
        o_j = aes_decryption(c_j, key)
        p_j = xor_bytes(o_j, c_j_1)
        plain += p_j
        c_j_1 = c_j

    plain = remove_padding(bytes(plain))
    
    return plain
