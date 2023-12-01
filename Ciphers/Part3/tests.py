import sys
import time
import os

sys.path.append('../Part1')
sys.path.append('../Part2')

from cbc_aes_implementation import aes_cbc_encryption, aes_cbc_decryption
from rsa_implementation import generate_prime_number, calculate_private_key, rsa_encrypt, rsa_decrypt

######  PART 1 AES TESTING  ######
print("\nAES ENCRYPTION SPEED TEST")

# Plaintext
plaintext = input("Introduce the message for AES Encryption: ")

# Key
key = b"16-byte key key "

# IV
iv = os.urandom(16)

# Number of times we compute encryption / decryption
n_tests = 100

start_time = time.time()

## ENCRYPTION ##
for i in range(n_tests):
    
    # CBC AES ENCRYPTION 
    ciphertext = aes_cbc_encryption(plaintext, key, iv)
    
total_time = time.time() - start_time

print("This is the average time for encrypting with AES:", total_time/n_tests, "seconds")


start_time = time.time()

## DECRYPTION ##
for i in range(n_tests):
    
    # CBC AES DECRYPTION 
    recovered_plaintext = aes_cbc_decryption(ciphertext, key, iv)
    
total_time = time.time() - start_time

print("This is the average time for decrypting with AES:", total_time/n_tests, "seconds")

# Print plaintext to terminal
print("You have a new message: ", recovered_plaintext)



######  PART 2 RSA TESTING  ######
print("\nRSA ENCRYPTION SPEED TEST")

rsa_key_size = 2048
prime_number_bit_length = rsa_key_size // 2

# Generate prime numbers p and q
p = generate_prime_number(prime_number_bit_length)
q = generate_prime_number(prime_number_bit_length)

# Calculate public key
n = p * q
e = 65537

# Calculate private key
d = calculate_private_key(e, p, q)

plaintext = input("Introduce your message for RSA Encryption: ")

start_time = time.time()

## ENCRYPTION ##
for i in range(n_tests):
    
    # RSA Encrypt
    ciphertext = rsa_encrypt(plaintext, e, n)
    
total_time = time.time() - start_time

print("This is the average time for encrypting with RSA:", total_time/n_tests, "seconds")

## DECRYPTION ##
for i in range(n_tests):
    
    # RSA Decrypt
    recovered_plaintext = rsa_decrypt(ciphertext, d, n)
    
total_time = time.time() - start_time

print("This is the average time for decrypting with RSA:", total_time/n_tests, "seconds")

print("Here is your message:", recovered_plaintext)

