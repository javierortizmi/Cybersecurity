from rsa_implementation import generate_prime_number, calculate_private_key

if __name__ == "__main__":
        
    rsa_key_size = 2048
    prime_number_bit_length = rsa_key_size // 2

    # Generate prime numbers p and q
    p = generate_prime_number(prime_number_bit_length)
    q = generate_prime_number(prime_number_bit_length)

    # Calculate public key
    n = p * q
    e = 65537   # Common secure practice nowadays

    f = open("files/public_key", "w")
    f.write(str(n) + "\n" + str(e))
    f.close()


    # Calculate private key
    d = calculate_private_key(e, p, q)

    f = open("files/private_key", "w")
    f.write(str(d))
    f.close()