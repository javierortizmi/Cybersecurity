# Signature Generation
def sign_message(message: str, private_key) -> int:
    message_bytes = message.encode()
    m = int.from_bytes(message_bytes, 'big')
    d, n = private_key
    signature = pow(m, d, n)    # s = m ^ d mod n
    return signature

# Signature Verification
def verify_signature(message: str, signature: int, public_key) -> bool:
    message_bytes = message.encode()
    m = int.from_bytes(message_bytes, 'big')
    e, n = public_key
    m_prime = pow(signature, e, n)  # m = s ^ e mod n
    return m_prime == m