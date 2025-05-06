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
    """Generate 16 48-bit subkeys from 64-bit input key
    
    Key Schedule Bit Shifting:
    1. Initial 64-bit key is reduced to 56 bits by PC-1
    2. 56 bits are split into two 28-bit halves
    3. Each round, both halves are shifted left by 1 or 2 bits
    4. Shifts for rounds 1,2,9,16 are 1 bit; all others are 2 bits
    5. After shifting, PC-2 selects 48 bits for the round key
    """
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

def rotate_left(bits, positions):
    """Helper function to perform circular left rotation of bits"""
    return bits[positions:] + bits[:positions]

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

def generate_random_key():
    """Generate a random 64-bit key with proper parity bits"""
    # Generate 56 random bits
    key_56 = format(random.getrandbits(56), '056b')
    # Add parity bits
    return generate_key_with_parity(key_56)

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
    """Convert 8 characters to 64-bit binary"""
    if len(text) != 8:
        raise ValueError("Input must be exactly 8 characters")
    return ''.join(format(ord(c), '08b') for c in text)

def bin_to_str(binary):
    """Convert 64-bit binary to 8 characters"""
    if len(binary) != 64:
        raise ValueError("Binary input must be exactly 64 bits")
    try:
        return ''.join(chr(int(binary[i:i+8], 2)) for i in range(0, 64, 8))
    except ValueError:
        return "ERROR: Binary conversion issue!"

def triple_des_encrypt(plaintext, key1, key2, key3):
    """Triple DES encryption: EDE (Encrypt-Decrypt-Encrypt) mode"""
    plaintext_bin = str_to_bin(plaintext)
    enc1 = des_encrypt_block(plaintext_bin, key1)
    dec2 = des_decrypt_block(enc1, key2)
    cipher = des_encrypt_block(dec2, key3)
    return cipher

def triple_des_decrypt(ciphertext, key1, key2, key3):
    """Triple DES decryption: EDE (Encrypt-Decrypt-Encrypt) mode"""
    dec3 = des_decrypt_block(ciphertext, key3)
    enc2 = des_encrypt_block(dec3, key2)
    plaintext_bin = des_decrypt_block(enc2, key1)
    return bin_to_str(plaintext_bin)

def save_keys(key1, key2, key3, filename="3des_keys.txt"):
    with open(filename, "w") as f:
        f.write(f"{key1}\n{key2}\n{key3}\n")

def load_keys(filename="3des_keys.txt"):
    with open(filename, "r") as f:
        lines = f.readlines()
        return lines[0].strip(), lines[1].strip(), lines[2].strip()

# === ENCRYPTION ===
print("=== Encryption Process ===")
plaintext = "HELLO123"
print("Original Text:", plaintext)
original_binary = str_to_bin(plaintext)

# Generate random 64-bit keys with parity bits
key1 = generate_random_key()
key2 = generate_random_key()
key3 = generate_random_key()
save_keys(key1, key2, key3)

ciphertext = triple_des_encrypt(plaintext, key1, key2, key3)
print("Ciphertext Binary:", ciphertext)

# === DECRYPTION ===
print("\n=== Decryption Process ===")
key1_loaded, key2_loaded, key3_loaded = load_keys()
decrypted_text = triple_des_decrypt(ciphertext, key1_loaded, key2_loaded, key3_loaded)
print("Decrypted Text:", decrypted_text)

if decrypted_text != "ERROR: Binary conversion issue!":
    decrypted_binary = str_to_bin(decrypted_text)
    print("Original Binary: ", original_binary)
    print("Decrypted Binary:", decrypted_binary)
    print("Binaries Match:", original_binary == decrypted_binary)