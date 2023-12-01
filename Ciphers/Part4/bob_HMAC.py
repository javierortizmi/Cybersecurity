from HMAC_implementation import hmac
from cryptography.hazmat.primitives import hashes

if __name__ == "__main__":

    f = open("files/secret_key", "rb")
    key = f.read()
    f.close()

    f = open("files/mactext", "rb")
    mactext = f.readlines()
    message = mactext[0].rstrip(b"\n")
    print("This is the message:", message.decode())
    expected_mac_tag = mactext[1]
    print("This was the result of Alice HMAC", expected_mac_tag.hex())
    f.close()
    
    mac_tag = hmac(hashes.SHA256(), key, message)
    print("This is the result of Bob HMAC:", mac_tag.hex())
    
    assert (expected_mac_tag == mac_tag)    # This should NOT give any error
    
    print("\nNow we can try to change the message and compute the HMAC")
    
    infected_message = b"This is NOT the original message"
    infected_hmac_tag = hmac(hashes.SHA256(), key, infected_message)
    
    print("This is the result of the HMAC if the message is changed:", infected_hmac_tag.hex(), "\n")
    
    assert (expected_mac_tag == infected_message)   # This should give an error