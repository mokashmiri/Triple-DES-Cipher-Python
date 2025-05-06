import random
import os

# Initial and Final Permutation Tables (Fixed)
IP = [58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
      62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
      57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
      61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7]

FP = [40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
      38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
      36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
      34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25]

# PC-1 table - Permuted Choice 1 for key schedule (reduces 64 bits to 56)
PC1 = [57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
       10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
       63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
       14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4]

# PC-2 table - Permuted Choice 2 for key schedule (reduces 56 bits to 48)
PC2 = [14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10,
       23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
       41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
       44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32]

# Expansion table - expands 32 bits to 48 bits
E = [32, 1, 2, 3, 4, 5,
     4, 5, 6, 7, 8, 9,
     8, 9, 10, 11, 12, 13,
     12, 13, 14, 15, 16, 17,
     16, 17, 18, 19, 20, 21,
     20, 21, 22, 23, 24, 25,
     24, 25, 26, 27, 28, 29,
     28, 29, 30, 31, 32, 1]

# S-boxes - each S-box maps 6 bits to 4 bits
S_BOXES = [
    # S1
    [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
    ],
    # S2
    [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
    ],
    # S3
    [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
    ],
    # S4
    [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
    ],
    # S5
    [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
    ],
    # S6
    [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
    ],
    # S7
    [
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
    ],
    # S8
    [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
    ]
]

# P-box permutation table
P = [16, 7, 20, 21, 29, 12, 28, 17,
     1, 15, 23, 26, 5, 18, 31, 10,
     2, 8, 24, 14, 32, 27, 3, 9,
     19, 13, 30, 6, 22, 11, 4, 25]

def permute(block, table):
    return ''.join(block[i - 1] for i in table)

def generate_subkeys(key):
    '''Generate 16 48-bit subkeys from 64-bit input key
    Key Schedule Bit Shifting:
    1. Initial 64-bit key is reduced to 56 bits by PC-1
    2. 56 bits are split into two 28-bit halves
    3. Each round, both halves are shifted left by 1 or 2 bits
    4. Shifts for rounds 1,2,9,16 are 1 bit; all others are 2 bits
    5. After shifting, PC-2 selects 48 bits for the round key
    '''

    # First apply PC1 to get 56 bits
    key_56 = permute(key, PC1)
    
    # Split into left and right halves (28 bits each)
    left = key_56[:28]
    right = key_56[28:]
    
    # Generate 16 subkeys
    subkeys = []
    # Number of bit positions to shift left each round
    # 1 for rounds 1,2,9,16; 2 for all others
    shifts = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]
    
    for round_num, shift in enumerate(shifts, 1):
        # Circular left shift on each half
        left = left[shift:] + left[:shift]  # Left half shift
        right = right[shift:] + right[:shift]  # Right half shift
        
        # Combine halves and apply PC2 to get 48-bit round key
        combined = left + right
        subkey = permute(combined, PC2)
        subkeys.append(subkey)
    
    return subkeys

#parity bits are redundant in a modern software implementation due to the very limited probability of bit flipping in the key
def generate_key_with_parity(key_56):
    """Generate 64-bit key from 56-bit key by adding parity bits"""
    key_64 = ""
    pos = 0
    for i in range(8):  # Process 8 bytes
        # Take 7 bits from the 56-bit key
        byte = key_56[i*7:(i+1)*7]
        # Count 1s in the byte
        count = sum(1 for bit in byte if bit == '1')
        # Add parity bit (odd parity)
        parity = '1' if count % 2 == 0 else '0'
        key_64 += byte + parity
    return key_64

#given the redundancy of the parity bit we rather produce a 64 bit random key of which 8 bit won't be used
def generate_random_key():
    """Generate a random 64-bit key w/o proper parity bits"""
    key= format(random.getrandbits(64), '064b')
    return key

def apply_sbox(input_6bits, sbox_num):
    """Apply a specific S-box to 6-bit input"""
    # Row is determined by outer bits (first and last)
    row = int(input_6bits[0] + input_6bits[5], 2)
    # Column is determined by middle 4 bits
    col = int(input_6bits[1:5], 2)
    # Get 4-bit output from S-box
    output = S_BOXES[sbox_num][row][col]
    return format(output, '04b')

def feistel_function(right, subkey):
    """Feistel (F) function implementation with full S-box substitution"""
    expanded = permute(right, E)
    xored = format(int(expanded, 2) ^ int(subkey, 2), '048b')
    sbox_output = ""
    for i in range(8):
        six_bits = xored[i*6:(i+1)*6]
        sbox_output += apply_sbox(six_bits, i)
    return permute(sbox_output, P)

def des_encrypt_block(plaintext_block, key):
    """DES encryption of a 64-bit block using 64-bit key"""
    if len(plaintext_block) != 64:
        raise ValueError("Plaintext block must be 64 bits")
    if len(key) != 64:
        raise ValueError("Key must be 64 bits")
    
    # Generate subkeys
    subkeys = generate_subkeys(key)
    
    # Initial permutation
    block = permute(plaintext_block, IP)
    left, right = block[:32], block[32:]
    
    # 16 rounds
    for i in range(16):
        next_left = right
        f_result = feistel_function(right, subkeys[i])
        next_right = format(int(left, 2) ^ int(f_result, 2), '032b')
        left, right = next_left, next_right
    
    # Final permutation (with 32-bit swap)
    return permute(right + left, FP)

def des_decrypt_block(ciphertext_block, key):
    """DES decryption of a 64-bit block using 64-bit key"""
    if len(ciphertext_block) != 64:
        raise ValueError("Ciphertext block must be 64 bits")
    if len(key) != 64:
        raise ValueError("Key must be 64 bits")
    
    # Generate subkeys
    subkeys = generate_subkeys(key)
    # For decryption, use subkeys in reverse order
    subkeys.reverse()
    
    # Initial permutation
    block = permute(ciphertext_block, IP)
    left, right = block[:32], block[32:]
    
    # 16 rounds with reversed subkeys
    for i in range(16):
        next_left = right
        f_result = feistel_function(right, subkeys[i])
        next_right = format(int(left, 2) ^ int(f_result, 2), '032b')
        left, right = next_left, next_right
    
    # Final permutation (with 32-bit swap)
    return permute(right + left, FP)

def str_to_bin(text):
    """Converts string to binary rappresentation"""
    return ''.join(format(ord(c), '08b') for c in text)

def bin_to_str(binary):
    if len(binary) % 8 != 0:
        raise ValueError("Binary string length must be a multiple of 8.")
    try:
        return ''.join(chr(int(binary[i:i+8], 2)) for i in range(0, len(binary), 8))
    except ValueError:
        return "ERROR: Binary conversion issue!"

def triple_des_encrypt_block(plaintext, key1, key2, key3):
    """Triple DES encryption: EDE (Encrypt-Decrypt-Encrypt) mode"""
    plaintext_bin = str_to_bin(plaintext)
    enc1 = des_encrypt_block(plaintext_bin, key1)
    dec2 = des_decrypt_block(enc1, key2)
    cipher = des_encrypt_block(dec2, key3)
    return cipher

def triple_des_decrypt_block(ciphertext, key1, key2, key3):
    """Triple DES decryption: EDE (Encrypt-Decrypt-Encrypt) mode"""
    dec3 = des_decrypt_block(ciphertext, key3)
    enc2 = des_encrypt_block(dec3, key2)
    plaintext_bin = des_decrypt_block(enc2, key1)
    return bin_to_str(plaintext_bin)

def save_keys(key1, key2, key3, filename="3des_keys.txt"):
    try:
        with open(filename, "w") as f:
            f.write(f"{key1}\n{key2}\n{key3}\n")
    except IOError:
        raise IOError("Failed to save keys to file.")

def load_keys(filename="3des_keys.txt"):
    try:
        with open(filename, "r") as f:
            lines = f.readlines()
            if len(lines) != 3:
                raise ValueError("Key file must contain exactly 3 keys.")
            return lines[0].strip(), lines[1].strip(), lines[2].strip()
    except IOError:
        raise IOError("Failed to load keys from file.")

'''but to encrypt a information longer than 64bits we need to give the string some padding,
padding referes to the addition of extra bits to the string to make it a multiple of 64.
we later remove this padding after decryption. to keep track of how many bits we added
we add a padding length byte at the end of the string.'''
def pad(bin, block_size=64):
    """
    Apply padding to the input data.
    :param data: Binary string representing the data to be padded.
    :param block_length: The desired block length (e.g., 64 bits).
    :return: Padded binary string.
    """
    pad_lenght= block_size - (len(bin) % block_size)
    # Append a single "1" bit
    padded_data = bin  + "1"
    if pad_lenght!=1:
        # Add enough "0" bits to make it a multiple of the block length
        padded_data += "0" * (pad_lenght - 1)
    
    return padded_data

def unpad(padded_bin):
    """
    Remove padding from the input data.
    :param data: Binary string with padding applied.
    :param block_length: The block length used during padding (e.g., 64 bits).
    :return: Unpadded binary string.
    """
    # Remove trailing "0" bits and the last "1" bit
    unpadded_bin = padded_bin.rstrip("0")  # Remove all trailing "0" bits
    unpadded_bin = unpadded_bin[:-1]  # Remove the final "1" bit (padding marker)
    
    return unpadded_bin

def triple_des_encrypt(plaintext, key1, key2, key3):
    """Triple DES encryption: EDE (Encrypt-Decrypt-Encrypt) mode"""
    """Encrypt text longer than 64 bits iteratively."""
    plaintext_bin = str_to_bin(plaintext)
    padded_bin=pad(plaintext_bin)
    cipher_bin = ""
    for i in range(0, len(padded_bin), 64):
        chunk = padded_bin[i:i+64]
        enc_chunk = triple_des_encrypt_block(bin_to_str(chunk), key1, key2, key3)
        cipher_bin += enc_chunk
    return cipher_bin

def triple_des_decrypt(ciphertext, key1, key2, key3):
    """Triple DES decryption: EDE (Encrypt-Decrypt-Encrypt) mode"""
    """Decrypt text longer than 64 bits iteratively."""
    padded_bin = ""
    for i in range(0, len(ciphertext), 64):
        chunk = ciphertext[i:i+64]
        dec_chunk = triple_des_decrypt_block(chunk, key1, key2, key3)
        padded_bin += str_to_bin(dec_chunk)
    plaintext_bin = unpad(padded_bin)
    return bin_to_str(plaintext_bin)

def read_plaintext_from_file(filename):
    """Read plaintext from a file"""
    try:
        with open(filename, 'r') as file:
            return file.read().strip()
    except IOError:
        raise IOError(f"Could not read file: {filename}")

def create_empty_file():
    """Create empty files for user input"""
    try:
        # Create input.txt
        with open('input.txt', 'w') as file:
            file.write('')
        # Create 3des_keys.txt with example
        with open('3des_keys.txt', 'w') as file:
            file.write('0101010101010101010101010101010101010101010101010101010101010101\n')
            file.write('1010101010101010101010101010101010101010101010101010101010101010\n')
            file.write('1111000011110000111100001111000011110000111100001111000011110000\n')
        
        current_path = os.getcwd()
        print("\nInstructions:")
        print(f"1. Open 'input.txt' in this path: {current_path}")
        print("2. Paste your plaintext into input.txt and save it")
        print(f"3. Open '3des_keys.txt' in this path: {current_path}")
        print("4. Replace the example keys with your three 64-bit keys (one per line)")
        print("5. Save both files")
        print("6. Press Enter in this terminal to start the encryption process...")
        input()
    except IOError:
        raise IOError("Could not create input files")

def read_keys_from_file():
    """Read three 64-bit keys from file"""
    try:
        with open('3des_keys.txt', 'r') as file:
            keys = file.readlines()
            if len(keys) != 3:
                raise ValueError("3des_keys.txt must contain exactly 3 keys (one per line)")
            
            keys = [key.strip() for key in keys]
            for key in keys:
                if len(key) != 64:
                    raise ValueError("Each key must be exactly 64 bits long")
                if not all(bit in '01' for bit in key):
                    raise ValueError("Keys must contain only 0s and 1s")
            
            return keys[0], keys[1], keys[2]
    except IOError:
        raise IOError("Could not read 3des_keys.txt")

# === ENCRYPTION ===
print("=== 3DES Encryption Process ===")
print("This program will encrypt text using Triple DES (3DES) algorithm.")

try:
    # Create empty files and wait for user input
    create_empty_file()
    
    # Read the plaintext from the file
    plaintext = read_plaintext_from_file('input.txt')
    if not plaintext:
        raise ValueError("The input file is empty. Please add some text to encrypt.")
    
    print("\nText read from file:", plaintext)
    
    # Read keys from file
    print("\nReading keys from 3des_keys.txt...")
    key1, key2, key3 = read_keys_from_file()
    
    # Encrypt
    print("\nEncrypting...")
    ciphertext = triple_des_encrypt(plaintext, key1, key2, key3)
    print("\nCiphertext (binary):", ciphertext)
    
    # === DECRYPTION ===
    print("\n=== 3DES Decryption Process ===")
    print("Decrypting...")
    decrypted_text = triple_des_decrypt(ciphertext, key1, key2, key3)
    print("\nDecrypted Text:", decrypted_text)
    
    # Verify
    if decrypted_text != "ERROR: Binary conversion issue!":
        print("\nVerification:")
        print("Original Text:", plaintext)
        print("Decrypted Text:", decrypted_text)
        print("Match:", plaintext == decrypted_text)
    
except Exception as e:
    print(f"\nError: {str(e)}")
    print("Please check your input files and try again.")