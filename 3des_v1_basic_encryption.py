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

def permute(block, table):
    return ''.join(block[i - 1] for i in table)

def feistel_function(right, key):
    right_int = int(right, 2)
    key_int = int(key, 2)
    result = right_int ^ key_int
    return format(result, '032b')

def des_encrypt_block(plaintext_block, key):
    if len(plaintext_block) != 64:
        raise ValueError("Plaintext block must be 64 bits")
    block = permute(plaintext_block, IP)
    left, right = block[:32], block[32:]
    
    # Using the same number of rounds for encrypt and decrypt
    rounds = 16  # Standard DES uses 16 rounds
    for _ in range(rounds):
        next_left = right
        f_result = feistel_function(right, key)
        next_right = format(int(left, 2) ^ int(f_result, 2), '032b')
        left, right = next_left, next_right
        
    # In DES, we swap the final L and R before applying FP
    return permute(right + left, FP)  # Note the swap here

def des_decrypt_block(ciphertext_block, key):
    if len(ciphertext_block) != 64:
        raise ValueError("Ciphertext block must be 64 bits")
    block = permute(ciphertext_block, IP)
    # In decryption, we start with the opposite order
    right, left = block[:32], block[32:]
    
    # Same number of rounds as encryption
    rounds = 16
    for _ in range(rounds):
        next_right = left
        f_result = feistel_function(left, key)
        next_left = format(int(right, 2) ^ int(f_result, 2), '032b')
        right, left = next_right, next_left
        
    return permute(left + right, FP)

def str_to_bin(text):
    if len(text) != 8:
        raise ValueError("Input must be exactly 8 characters")
    return ''.join(format(ord(c), '08b') for c in text)

def bin_to_str(binary):
    if len(binary) != 64:
        raise ValueError("Binary input must be exactly 64 bits")
    try:
        return ''.join(chr(int(binary[i:i+8], 2)) for i in range(0, 64, 8))
    except ValueError:
        return "ERROR: Binary conversion issue!"

def triple_des_encrypt(plaintext, key1, key2, key3):
    plaintext_bin = str_to_bin(plaintext)
    enc1 = des_encrypt_block(plaintext_bin, key1)
    dec2 = des_decrypt_block(enc1, key2)
    cipher = des_encrypt_block(dec2, key3)
    return cipher

def triple_des_decrypt(ciphertext, key1, key2, key3):
    # Correct order for Triple DES decryption: decrypt with key3, encrypt with key2, decrypt with key1
    dec3 = des_decrypt_block(ciphertext, key3)
    enc2 = des_encrypt_block(dec3, key2)
    plaintext_bin = des_decrypt_block(enc2, key1)
    return bin_to_str(plaintext_bin)

def generate_random_key(length=64):
    return format(random.getrandbits(length), f'0{length}b')

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

# Generate and save random keys
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