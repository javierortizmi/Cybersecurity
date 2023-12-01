from cryptography.hazmat.primitives import hashes


def xor(a: bytes, b: bytes) -> bytes:
    return bytes([x ^ y for (x, y) in zip(a, b)])


def H(H_A, message):
    H = hashes.Hash(H_A)
    H.update(message)
    return H.finalize()


def hmac(H_A, K, text):
    # HMAC Parameters and Symbols
    B, L = H_A.block_size, H_A.digest_size
    ipad = b"\x36" * B
    opad = b"\x5c" * B

    # HMAC SPECIFICATION
    if len(K) == B:
        K_0 = K
    elif len(K) > B:
        K_0 = H(H_A, K) + b"\x00" * (B - L)
    else:
        K_0 = K + b"\x00" * (B - len(K))

    return H(H_A, xor(K_0, opad) + H(H_A, xor(K_0, ipad) + text))