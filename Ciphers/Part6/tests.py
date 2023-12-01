import sys
import time
from cryptography.hazmat.primitives import hashes

sys.path.append('../Part2')
sys.path.append('../Part4')
sys.path.append('../Part5')

from HMAC_implementation import hmac
from rsa_implementation import generate_prime_number, calculate_private_key
from digital_signature_implementation import sign_message, verify_signature

# Number of times we compute the tests
n_tests = 100

## PART 4 HMAC TEST ##
print("\nHMAC SPEED TEST")

key = b"16-byte key key "
message = input("Enter your message: ").encode()    # 7-byte message

start_time = time.time()

for i in range(n_tests):
    mac_tag = hmac(hashes.SHA256(), key, message)
    
total_time = time.time() - start_time

print("This is the average time for the HMAC function:", total_time/n_tests, "seconds")

## PART 5 TEST ##
print("\nRSA DIGITAL SIGNATURE SPEED TEST")

# Key Generation (Using the existing functions)
rsa_key_size = 2048
prime_number_bit_length = rsa_key_size // 2
p = generate_prime_number(prime_number_bit_length)
q = generate_prime_number(prime_number_bit_length)
n = p * q

e = 65537  # A common choice for the public exponent

# Calculate private key
d = calculate_private_key(e, p, q)
private_key = d, n
public_key = e, n

message = input("Introduce your message: ") # 7-byte message

start_time = time.time()

for i in range(n_tests):
    signature = sign_message(message, private_key)
    
total_time = time.time() - start_time

print("This is the average time for the RSA signature:", total_time/n_tests, "seconds\n")

start_time = time.time()

for i in range(n_tests):
    verify_signature(message, signature, public_key)
    
total_time = time.time() - start_time

print("This is the average time for verifying the RSA signature:", total_time/n_tests, "seconds\n")