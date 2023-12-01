from digital_signature_implementation import sign_message

# Retrieve private key
f = open("files/private_key", "r")
private_key = f.readlines()
n = int(private_key[0])
d = int(private_key[1]) 
private_key = d, n
f.close()

# Ask for a message
message = input("Introduce your message: ")
signature = sign_message(message, private_key)

f = open("files/sigtext", "w")
f.write(str(message) + "\n" + str(signature))
f.close()
