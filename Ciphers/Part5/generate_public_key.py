import sys

sys.path.append('../Part2')

from rsa_implementation import generate_prime_number, calculate_private_key

# Key Generation (Using the existing functions)
rsa_key_size = 2048
prime_number_bit_length = rsa_key_size // 2
p = generate_prime_number(prime_number_bit_length)
q = generate_prime_number(prime_number_bit_length)
n = p * q

e = 65537  # A common choice for the public exponent

f = open("files/public_key", "w")
f.write(str(n) + "\n" + str(e))
f.close()


# Calculate private key
d = calculate_private_key(e, p, q)

f = open("files/private_key", "w")
f.write(str(n) + "\n" + str(d))
f.close()