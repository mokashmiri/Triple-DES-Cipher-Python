# 🔐 Triple DES (3DES) Encryption in Python

This repository documents the complete development of the **Triple DES (3DES)** encryption algorithm in Python. It follows a step-by-step implementation journey, demonstrating how DES and 3DES work internally — from basic permutation logic to full Feistel networks and key scheduling.

The project is organized into versions, each showing the progression toward a secure and complete final implementation.

---

## 📚 Project Overview

**Triple DES (3DES)** is a symmetric-key block cipher which applies the standard DES algorithm three times to each data block. DES operates on 64-bit blocks using a 56-bit key (plus 8 parity bits). To overcome DES’s vulnerabilities, 3DES uses a sequence of Encrypt–Decrypt–Encrypt (EDE) with three different keys.

---

## 🛠️ Features Implemented

- ✅ DES block encryption and decryption (Feistel structure)
- ✅ Key generation with parity support
- ✅ Subkey scheduling (PC-1, PC-2)
- ✅ Initial and final permutations (IP, FP)
- ✅ Full S-box and P-box logic
- ✅ 16 rounds of encryption/decryption
- ✅ Triple DES mode (EDE: Encrypt-Decrypt-Encrypt)
- ✅ Save/load key functionality
- ✅ Bit-level operations using Python standard libraries
- 🚧 Padding support under development

---

## 📂 Version Report

### 🔹 Version 1 – `3des_v1_basic_encryption.py`

- Introduced a functional DES encryption and decryption pipeline.
- Simplified Feistel function: XOR without S-boxes.
- Basic implementation of Triple DES using 3 keys.
- Key generation and file I/O via `.txt` file.
- Supports string-to-binary and binary-to-string conversion.

> ✅ Achieved: Basic encryption/decryption works  
> 🚫 Lacks: S-boxes, full DES key scheduling, permutations

---

### 🔹 Version 2 – `3des_v2_padding_attempt.py`

- Introduced concept of padding for plaintext shorter than 64 bits.
- Focused on splitting plaintext into 64-bit chunks.
- Implementation not finalized, but useful for future direction.

> ✅ Introduced padding functions  
> 🚫 Not production-ready; not integrated into full pipeline

---

### 🔹 Version 3 – `3des_v3_refactored_key_schedule.py`

- Major refactoring:
  - Added proper PC-1 and PC-2 permutation tables
  - Included subkey generation with rotation rules
- Introduced full S-box logic (8 S-boxes)
- Integrated P-box permutation
- Feistel function implemented as per DES standard

> ✅ DES subkeys and S-boxes working  
> 🚫 Still missing proper triple-layer 3DES logic

---

### 🔹 Version 4 – `3des_v4_near_final_version.py`

- Improved structure and readability
- Finalized permutation logic for IP and FP
- Combined all previous improvements into a unified DES encryption/decryption pipeline
- Functions now reusable and modular

> ✅ Full single DES encryption and decryption  
> 🚫 3DES wrapping logic added manually but not centralized

---

### 🔹 Version 5 – `3des_v5_final_complete_5may.py`

- ✅ Finalized and cleaned implementation
- Full Triple DES (EDE mode) with:
  - Key generation
  - Subkey scheduling
  - S-box/P-box processing
  - Initial/Final Permutation (IP/FP)
  - Modular encrypt/decrypt functions
- Tested with fixed plaintext and validated correct round-trip decryption
- Error handling added for wrong input lengths

> 🎯 This version is recommended for practical use, testing, or as a study reference.

---

## 🧪 Sample Output

=== Encryption Process ===
Original Text: HELLO123
Ciphertext Binary: 110001010101011101100...
=== Decryption Process ===
Decrypted Text: HELLO123
Binaries Match: True
