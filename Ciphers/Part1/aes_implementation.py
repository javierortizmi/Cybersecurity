from box import s_box, inv_s_box    # We import the (Inverse) Substitution Box

##########   AES ENCRYPTION   ##########

## KEY EXPANSION ##

# Substitute Word #
# This function takes a 4-byte word (represented as a list of integers) as input
# It performs a substitution on each byte of the input word using the S-box
# Each byte of the input word is replaced by a corresponding value from the S-box
def sub_word(word: [int]) -> bytes:
    substituted_word = bytes(s_box[i] for i in word)
    return substituted_word     # The result is a new 4-byte word

# Round Constant #
# The i value determines a value for the Rcon in the key expansion process
# It uses a pre-defined Rcon lookup table to find the appropriate value for the given i
# The Rcon values are used to ensure that each round key is different during key expansion.
def rcon(i: int) -> bytes:
    rcon_lookup = bytearray.fromhex('01020408102040801b36') # From Wikipedia
    rcon_value = bytes([rcon_lookup[i-1], 0, 0, 0])         
    return rcon_value   # returns a 4-byte value containing the Rcon value and three zero bytes

# XOR Bytes #
# This function takes two bytes objects, a and b, as input
# It performs a bitwise XOR operation between the corresponding bytes of a and b
# Returns a new bytes object containing the result of the XOR operation
def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes([x ^ y for (x, y) in zip(a, b)]) # zip returns an iterator of tuples (finite and ordered list)   

# Rotation of input Word #
# This function takes a 4-byte word (represented as a list of integers) as input
# Tt shifts the elements in the list to the left by one position and wraps the last element to the beginning
def rot_word(word: [int]) -> [int]:
    return word[1:] + word[:1]  # Returns the result as a new 4-byte word

# Key Expansion #
# Responsible for expanding the encryption key into a set of round keys
# takes the original encryption key as input (key), which is typically 16, 24, or 32 bytes long
def key_expansion(key: bytes, nb: int = 4) -> [[[int]]]:

    nk = len(key) // 4  # Determines the number of 32-bit (4-byte) words in the key (number of keys)

    key_bit_length = len(key) * 8   # Transform from bytes to bits

    # Decide the number of rounds (nr) depending on the length bits of the input key 
    if key_bit_length == 128:
        nr = 10
    elif key_bit_length == 192:
        nr = 12
    else:  # 256-bit keys
        nr = 14

    # convert a bytes object (key) into a 4x4 matrix (w) of integers
    w = state_from_bytes(key)

    # The key expansion process involves using the Rcon values, the sub_word function, and XOR operations 
    # With those, we can generate a series of round keys
    for i in range(nk, nb * (nr + 1)):  # nb = number of columns in the state
        temp = w[i-1]   # temporary 4-byte word equal to the previous word in the key schedule (w[i-1])
        if i % nk == 0:
            temp = xor_bytes(sub_word(rot_word(temp)), rcon(i // nk))
        elif nk > 6 and i % nk == 4:
            temp = sub_word(temp)
        w.append(xor_bytes(w[i - nk], temp))

    # These round keys are returned as a list of 4x4 matrices, where each matrix represents a round key
    return [w[i*4:(i+1)*4] for i in range(len(w) // 4)]
        

## STATE FROM BYTES / BYTES FROM STATE ##

# State From Bytes #
# Convert a bytes object (data) into a 4x4 matrix (state) of integers
def state_from_bytes(data: bytes) -> [[int]]:
    state = [data[i*4:(i+1)*4] for i in range(len(data) // 4)]
    return state

# Bytes From State #
# The bytes_from_state function takes a 4x4 matrix of integers,
# which typically represents the state of data during AES encryption or decryption, 
# and converts it into a single bytes object
def bytes_from_state(state: [[int]]) -> bytes:
    return bytes(state[0] + state[1] + state[2] + state[3])


## SUB BYTES ##
# Each byte of the state matrix is substituted with a corresponding byte from the S-box
# Providing non-linear confusion in the data
def sub_bytes(state: [[int]]):
    for r in range(len(state)):
        state[r] = [s_box[state[r][c]] for c in range(len(state[0]))]

## SHIFT ROWS ##
# The bytes in the rows of the state matrix are shifted to the left by varying amounts
# Providing transposition and diffusion
def shift_rows(state: [[int]]):
    # [00, 10, 20, 30]     [00, 10, 20, 30]
    # [01, 11, 21, 31] --> [11, 21, 31, 01]
    # [02, 12, 22, 32]     [22, 32, 02, 12]
    # [03, 13, 23, 33]     [33, 03, 13, 23]
    state[0][1], state[1][1], state[2][1], state[3][1] = state[1][1], state[2][1], state[3][1], state[0][1]
    state[0][2], state[1][2], state[2][2], state[3][2] = state[2][2], state[3][2], state[0][2], state[1][2]
    state[0][3], state[1][3], state[2][3], state[3][3] = state[3][3], state[0][3], state[1][3], state[2][3]

## MIX COLUMNS ##
# It involves matrix multiplication over a finite field
# Ensuring that the bits from different bytes influence each other
# Xtime #
# It performs a bitwise XOR with the hexadecimal constant 0x1b
# Used to multiply elements in the MixColumns operation to provide diffusion
def xtime(a: int) -> int:
    if a & 0x80:
        return ((a << 1) ^ 0x1b) & 0xff
    return a << 1

# Mix Column #
# Takes a single column and performs the xtime operation on all the rows of that column
def mix_column(col: [int]):
    c_0 = col[0]
    all_xor = col[0] ^ col[1] ^ col[2] ^ col[3] # Calculates the XOR of all elements in the column
    col[0] ^= all_xor ^ xtime(col[0] ^ col[1])  # Apply specific transformations 
    col[1] ^= all_xor ^ xtime(col[1] ^ col[2])  # to each element in the column
    col[2] ^= all_xor ^ xtime(col[2] ^ col[3])
    col[3] ^= all_xor ^ xtime(c_0 ^ col[3])     # c_0 = col[0]

# Mix Columns #
# Perform the Mix Column operation to all the columns in the state matrix
def mix_columns(state: [[int]]):
    for r in state:
        mix_column(r)
    
## ADD ROUND KEY ##
# Combine the state matrix with a round-specific key from the key schedule
# Introducing the secret key's influence into the encryption process
def add_round_key(state: [[int]], key_schedule: [[[int]]], round: int):
    round_key = key_schedule[round] # Select the round kwy from the keys matrix
    for r in range(len(state)):
        # performs a bitwise XOR operation (^) between the byte in the state matrix (state[r][c]) 
        # and the corresponding byte in the round key (round_key[r][c] 
        state[r] = [state[r][c] ^ round_key[r][c] for c in range(len(state[0]))]


## AES ENCRYPTION ##
def aes_encryption(data: bytes, key: bytes) -> bytes:

    # This step is the same from 'key_expansion' function 
    key_bit_length = len(key) * 8

    if key_bit_length == 128:
        nr = 10
    elif key_bit_length == 192:
        nr = 12
    else:  # 256-bit keys
        nr = 14

    # We get the matrix of data from a long bytesarray of data
    state = state_from_bytes(data)

    # Perform the key expansion operations to get a matrix of keys
    key_schedule = key_expansion(key)

    # Add the key to the first column of data
    add_round_key(state, key_schedule, round=0)

    # Keep performing the sequence of steps: 
    #    1: SubBytes (Substitution Layer)
    #    2: ShiftRows (Permutation Layer)
    #    3: MixColumns (Diffusion Layer)
    #    4: AddRoundKey (Key XOR) 
    # for all the columns
    for round in range(1, nr):
        sub_bytes(state)
        shift_rows(state)
        mix_columns(state)
        add_round_key(state, key_schedule, round)

    # There is a final step in which we repeat sub_bytes, shift_rows and add_round_key
    sub_bytes(state)
    shift_rows(state)
    add_round_key(state, key_schedule, round=nr)

    # Transform again the ciphertext matrix to a long bytesarray
    cipher = bytes_from_state(state)
    return cipher   # Return that bytesarray



######   DECRYPTION   ######

def inv_shift_rows(state: [[int]]) -> [[int]]:
    # [00, 10, 20, 30]     [00, 10, 20, 30]
    # [01, 11, 21, 31] <-- [11, 21, 31, 01]
    # [02, 12, 22, 32]     [22, 32, 02, 12]
    # [03, 13, 23, 33]     [33, 03, 13, 23]
    state[1][1], state[2][1], state[3][1], state[0][1] = state[0][1], state[1][1], state[2][1], state[3][1]
    state[2][2], state[3][2], state[0][2], state[1][2] = state[0][2], state[1][2], state[2][2], state[3][2]
    state[3][3], state[0][3], state[1][3], state[2][3] = state[0][3], state[1][3], state[2][3], state[3][3]
    return

def inv_sub_bytes(state: [[int]]) -> [[int]]:
    for r in range(len(state)):
        state[r] = [inv_s_box[state[r][c]] for c in range(len(state[0]))]


def xtimes_0e(b):
    # 0x0e = 14 = b1110 = ((x * 2 + x) * 2 + x) * 2
    return xtime(xtime(xtime(b) ^ b) ^ b)


def xtimes_0b(b):
    # 0x0b = 11 = b1011 = ((x*2)*2+x)*2+x
    return xtime(xtime(xtime(b)) ^ b) ^ b


def xtimes_0d(b):
    # 0x0d = 13 = b1101 = ((x*2+x)*2)*2+x
    return xtime(xtime(xtime(b) ^ b)) ^ b


def xtimes_09(b):
    # 0x09 = 9  = b1001 = ((x*2)*2)*2+x
    return xtime(xtime(xtime(b))) ^ b


def inv_mix_column(col: [int]):
    c_0, c_1, c_2, c_3 = col[0], col[1], col[2], col[3]
    col[0] = xtimes_0e(c_0) ^ xtimes_0b(c_1) ^ xtimes_0d(c_2) ^ xtimes_09(c_3)
    col[1] = xtimes_09(c_0) ^ xtimes_0e(c_1) ^ xtimes_0b(c_2) ^ xtimes_0d(c_3)
    col[2] = xtimes_0d(c_0) ^ xtimes_09(c_1) ^ xtimes_0e(c_2) ^ xtimes_0b(c_3)
    col[3] = xtimes_0b(c_0) ^ xtimes_0d(c_1) ^ xtimes_09(c_2) ^ xtimes_0e(c_3)
    
def inv_mix_columns(state: [[int]]) -> [[int]]:
    for r in state:
        inv_mix_column(r)


def inv_mix_column_optimized(col: [int]):
    u = xtime(xtime(col[0] ^ col[2]))
    v = xtime(xtime(col[1] ^ col[3]))
    col[0] ^= u
    col[1] ^= v
    col[2] ^= u
    col[3] ^= v


def inv_mix_columns_optimized(state: [[int]]) -> [[int]]:
    for r in state:
        inv_mix_column_optimized(r)
    mix_columns(state)
    

def aes_decryption(cipher: bytes, key: bytes) -> bytes:

    key_byte_length = len(key)
    key_bit_length = key_byte_length * 8

    # Decide number of rounds
    if key_bit_length == 128:
        nr = 10
    elif key_bit_length == 192:
        nr = 12
    else:  # 256-bit keys
        nr = 14

    # Now, we start decrypting from the end
    state = state_from_bytes(cipher)
    key_schedule = key_expansion(key)
    add_round_key(state, key_schedule, round=nr)

    for round in range(nr-1, 0, -1):
        inv_shift_rows(state)
        inv_sub_bytes(state)
        add_round_key(state, key_schedule, round)
        inv_mix_columns(state)

    inv_shift_rows(state)
    inv_sub_bytes(state)
    add_round_key(state, key_schedule, round=0)

    # Convert the matrix of plaintext to a bytesarray of plaintext
    plain = bytes_from_state(state)
    return plain    # Return plaintext (in bytes)