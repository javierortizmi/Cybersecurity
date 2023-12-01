from HMAC_implementation import hmac
from cryptography.hazmat.primitives import hashes

if __name__ == "__main__":

    
    key = b"This is  new key"
    f = open("files/secret_key", "wb")
    f.write(key)
    f.close()
    
    
    message = input("Enter your message: ").encode()
    
    mac_tag = hmac(hashes.SHA256(), key, message)
    
    f = open("files/mactext", "wb")
    f.write(message + b"\n" + mac_tag)
    
    f.close()