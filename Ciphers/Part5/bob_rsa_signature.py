from digital_signature_implementation import verify_signature

# Read public key
f = open("files/public_key", "r")
public_key = f.readlines()
n = int(public_key[0])
e = int(public_key[1]) 
public_key = e, n
f.close()

# Read sigtext
f = open("files/sigtext", "r")
sigtext = f.readlines()
message = sigtext[0].rstrip("\n")
signature = int(sigtext[1]) 
f.close()

# Check if the signature is valid
is_valid = verify_signature(message, signature, public_key)
print("Original message is ", message)

print(f"Signature is valid: {is_valid}")

# Try with another signature
print("Now we are going to change the signature")
other_signature = signature*3//7

is_valid = verify_signature(message, other_signature, public_key)
print(f"Signature is valid: {is_valid}")