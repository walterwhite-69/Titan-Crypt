<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8+-blue?style=for-the-badge&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License">
  <img src="https://img.shields.io/badge/Encryption-40%20Methods-red?style=for-the-badge&logo=shield&logoColor=white" alt="Methods">
  <img src="https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge" alt="Status">
</p>

<h1 align="center">
  <br>
  <pre>
▄▄▄█████▓
▓  ██▒ ▓▒
▒ ▓██░ ▒░
░ ▓██▓ ░ 
  ▒██▒ ░ 
  ▒ ░░   
    ░    
  ░      
  </pre>
  <br>
  TitanCrypt
  <br>
</h1>

<h4 align="center">A powerful Python code encryption & decryption tool with 40 encryption methods.</h4>

<p align="center">
  <a href="#-features">Features</a> •
  <a href="#-installation">Installation</a> •
  <a href="#-usage">Usage</a> •
  <a href="#-encryption-methods">Methods</a> •
  <a href="#-decryption">Decryption</a> •
  <a href="#%EF%B8%8F-limitations">Limitations</a>
</p>

---

## ✨ Features

- **40 Encryption Methods** - From basic obfuscation to military-grade multi-layer encryption
- **Universal Auto-Detection** - Automatically detects and decrypts ANY encrypted Python file
- **Self-Executing Output** - Encrypted files can run directly without manual decryption
- **Password Protection** - Secure your code with password-based encryption
- **Layer Analysis** - Detailed breakdown of encryption layers with confidence scoring
- **Beautiful TUI** - Clean, colorful terminal interface with rainbow banners

---

## 📦 Installation

```bash
# Clone the repository
git clone https://github.com/walterwhite-69/Titan-Crypt.git
cd Titan-Crypt

# Install dependencies
pip install rich pycryptodome cryptography
```

### Requirements
- Python 3.8+
- `rich` - Beautiful terminal formatting
- `pycryptodome` - AES, Blowfish, DES3, ChaCha20, Salsa20
- `cryptography` - Fernet encryption

---

## 🚀 Usage

```bash
python walter.py
```

### Main Menu
```
┌─────────────────────────────┐
│ [1] Encrypt Python Code     │
│ [2] Decrypt Python Code     │
│ [3] View Encryption Methods │
│ [4] About TitanCrypt        │
│ [0] Exit                    │
└─────────────────────────────┘
```

---

## 🔐 Encryption Methods

TitanCrypt offers **40 encryption methods** organized into 4 security tiers:

### 🟢 Level 1-10: Basic Obfuscation (No Password)

| ID | Method | Description | Reversible |
|:--:|--------|-------------|:----------:|
| 1 | **Base64** | Simple base64 encoding | ✅ Full |
| 2 | **Hex** | Hexadecimal encoding | ✅ Full |
| 3 | **ROT13** | Caesar cipher with 13 shift | ✅ Full |
| 4 | **Zlib** | Compression + Base64 | ✅ Full |
| 5 | **LZMA** | High-ratio compression + Base64 | ✅ Full |
| 6 | **XOR Basic** | XOR with fixed key (0x5A) | ✅ Full |
| 7 | **Base64 x3** | Triple base64 encoding | ✅ Full |
| 8 | **Reverse + B64** | Reversed bytes + Base64 | ✅ Full |
| 9 | **Hex + Zlib** | Hex encoding + Zlib compression | ✅ Full |
| 10 | **Multi-Layer Basic** | Base64 → Zlib → XOR → Base64 | ✅ Full |

> **Note:** These methods provide obfuscation only. No password required. Easy to reverse.

---

### 🟡 Level 11-20: Standard Encryption (Password Required)

| ID | Method | Description | Reversible |
|:--:|--------|-------------|:----------:|
| 11 | **AES-256** | Industry-standard AES encryption | ✅ Full |
| 12 | **Blowfish** | Classic Blowfish cipher | ✅ Full |
| 13 | **Triple DES** | 3DES with PKCS7 padding | ✅ Full |
| 14 | **ChaCha20** | Modern stream cipher | ✅ Full |
| 15 | **Fernet** | High-level symmetric encryption | ✅ Full |
| 16 | **AES + B64** | AES-256 + Base64 wrapper | ✅ Full |
| 17 | **Blowfish + Zlib** | Blowfish + Compression | ✅ Full |
| 18 | **XOR + AES** | XOR layer + AES-256 | ✅ Full |
| 19 | **Salsa20** | Salsa20 stream cipher | ✅ Full |
| 20 | **AES + Fernet** | Double encryption layer | ✅ Full |

> **Security:** Requires password. Uses PBKDF2 key derivation with 100,000 iterations.

---

### 🔴 Level 21-30: High Security (Multi-Layer)

| ID | Method | Description | Reversible |
|:--:|--------|-------------|:----------:|
| 21 | **Triple Layer** | Zlib → XOR → AES | ✅ Full |
| 22 | **Quad Layer** | Base64 → LZMA → Blowfish → Fernet | ✅ Full |
| 23 | **Substitution + AES** | Byte substitution + AES | ✅ Full |
| 24 | **XOR Chain** | Multiple XOR keys + Fernet | ✅ Full |
| 25 | **Compression Stack** | Zlib → LZMA → AES | ✅ Full |
| 26 | **Cipher Cascade** | AES → Blowfish → ChaCha20 | ✅ Full |
| 27 | **Obfuscation Max** | B64 → Hex → Zlib → LZMA → XOR → AES | ✅ Full |
| 28 | **Pentagon** | 5-layer encryption chain | ✅ Full |
| 29 | **Hexagon** | 6-layer with dual XOR | ✅ Full |
| 30 | **Marshal + AES** | Python bytecode + AES | ⚠️ Partial |

> **Warning:** Method 30+ uses `marshal.dumps()` which creates Python-version-specific bytecode.

---

### 🟣 Level 31-40: Ultra Security (Maximum Protection)

| ID | Method | Description | Reversible |
|:--:|--------|-------------|:----------:|
| 31 | **Marshal + Fernet** | Bytecode + Fernet | ⚠️ Partial |
| 32 | **Marshal + Blowfish** | Bytecode + Blowfish | ⚠️ Partial |
| 33 | **Marshal + ChaCha20** | Bytecode + ChaCha20 | ⚠️ Partial |
| 34 | **Marshal + Triple Layer** | Bytecode + AES + Fernet + Zlib | ⚠️ Partial |
| 35 | **Fortress** | Marshal + 5-cipher chain | ⚠️ Partial |
| 36 | **Citadel** | Marshal + 6-layer compression | ⚠️ Partial |
| 37 | **Chimera** | Marshal + Random layer ordering | ⚠️ Partial |
| 38 | **Hydra** | Marshal + 8-layer encryption | ⚠️ Partial |
| 39 | **Phoenix** | Marshal + 9-layer ultra chain | ⚠️ Partial |
| 40 | **Titan** | Marshal + 11-layer maximum security | ⚠️ Partial |

---

## 🔓 Decryption

### How Decryption Works

TitanCrypt uses **Universal Auto-Detection** to identify and decrypt encrypted files:

```
┌────────────────────────────────────────────────────┐
│                   DECRYPTION FLOW                  │
├────────────────────────────────────────────────────┤
│  1. Read encrypted file                            │
│  2. Detect file signature (TITAN_ENC_V1_)          │
│  3. Extract method ID and password length          │
│  4. Apply reverse transformations                  │
│  5. Output decrypted Python code                   │
└────────────────────────────────────────────────────┘
```

### Decryption Categories

| Category | Methods | Decryption Result |
|----------|:-------:|-------------------|
| **Full Recovery** | 1-29 | ✅ Original source code restored |
| **Bytecode Only** | 30-40 | ⚠️ Returns marshal bytecode (executable, not readable) |

---

## ⚠️ Limitations

### Marshal Bytecode (Methods 30-40)

Methods 30-40 use Python's `marshal` module to compile source code to bytecode before encryption. This creates **Python-version-specific** bytecode that:

```
┌─────────────────────────────────────────────────────────────┐
│                    MARSHAL LIMITATION                        │
├─────────────────────────────────────────────────────────────┤
│  ❌ Cannot be decompiled back to original source code       │
│  ❌ Bytecode format differs between Python versions         │
│  ❌ Python 3.11 bytecode ≠ Python 3.10 bytecode             │
│                                                              │
│  ✅ Encrypted files are SELF-EXECUTING                      │
│  ✅ Running the .py file executes original code             │
│  ✅ Decryption returns executable bytecode object           │
└─────────────────────────────────────────────────────────────┘
```

### What You Get After Decryption

| Method Range | Input | Decryption Output | Can Run? | Can Read? |
|:------------:|-------|-------------------|:--------:|:---------:|
| 1-29 | `hello.py` | Original source code | ✅ Yes | ✅ Yes |
| 30-40 | `hello.py` | Marshal bytecode | ✅ Yes | ❌ No |

### Cross-Version Compatibility

```
Encrypted on Python 3.11 → Decrypt on Python 3.11 ✅ Works
Encrypted on Python 3.11 → Decrypt on Python 3.10 ❌ May fail
```

---

## 🔥 Method 40: Titan Encryption

The ultimate encryption method with **11 layers**:

```
Original Code
     ↓
┌─────────────────────────────────────┐
│  1. marshal.dumps()    → Bytecode   │
│  2. LZMA compression   → Smaller    │
│  3. XOR (0xDE)         → Scrambled  │
│  4. Substitution       → Shuffled   │
│  5. AES-GCM            → Encrypted  │
│  6. Blowfish           → Double enc │
│  7. ChaCha20           → Stream enc │
│  8. Fernet             → High-level │
│  9. Zlib               → Compressed │
│  10. Base64            → Encoded    │
│  11. XOR (0xAD)        → Final pass │
└─────────────────────────────────────┘
     ↓
Titan-Encrypted Output
```

---

## 📁 Output File Format

Encrypted files are **self-executing Python scripts**:

```python
# Encrypted with TitanCrypt v1.0 - Method 40
import base64,zlib,lzma,struct,hashlib,marshal
# ... decryption logic ...

_DATA = "VElUQU5fRU5DX1YxXyg..."  # Encrypted payload

# Auto-executes on import
exec(compile(_decrypt().decode(), '<titan>', 'exec'))
```

### File Signature

All encrypted files contain the signature:
```
TITAN_ENC_V1_ + [Method ID: 2 bytes] + [Password Length: 2 bytes] + [Password] + [Encrypted Data]
```

---

## 💡 Best Practices

### Choosing an Encryption Method

| Use Case | Recommended Methods |
|----------|:------------------:|
| Quick obfuscation | 1-10 |
| Production code protection | 11-20 |
| Sensitive algorithms | 21-29 |
| Maximum security (source not needed) | 30-40 |

### Password Guidelines

- Use 12+ characters for methods 11+
- Mix uppercase, lowercase, numbers, symbols
- Avoid dictionary words
- Store passwords securely

---

## 🔧 Technical Details

### Cryptographic Primitives

| Algorithm | Key Size | Mode | Used In |
|-----------|:--------:|:----:|:-------:|
| AES-256 | 256-bit | CBC/GCM | 11, 16, 18, 20+ |
| Blowfish | 256-bit | CBC | 12, 17, 22+ |
| Triple DES | 192-bit | CBC | 13 |
| ChaCha20 | 256-bit | Stream | 14, 26+ |
| Salsa20 | 256-bit | Stream | 19 |
| Fernet | 256-bit | CBC | 15, 20+ |

### Key Derivation

```python
# PBKDF2-HMAC-SHA256
key = hashlib.pbkdf2_hmac(
    'sha256',
    password.encode(),
    salt,  # 16 random bytes
    100000,  # iterations
    dklen=32  # 256-bit key
)
```

---

## 📊 Security Comparison

```
Security Level
     ▲
     │
  🔒 │ ████████████████████████████████████████  Method 40 (Titan)
     │ ███████████████████████████████████████   Method 39 (Phoenix)
     │ ██████████████████████████████████████    Method 38 (Hydra)
     │ █████████████████████████████████████     Method 37 (Chimera)
     │ ████████████████████████████████████      Method 36 (Citadel)
     │ ███████████████████████████████████       Method 35 (Fortress)
     │ █████████████████████████████             Method 30 (Marshal+AES)
     │ ████████████████████████                  Method 26 (Cipher Cascade)
     │ ██████████████████████                    Method 20 (AES+Fernet)
     │ ████████████████                          Method 11 (AES-256)
     │ ███████                                   Method 10 (Multi-Layer Basic)
     │ ██                                        Method 1 (Base64)
     └──────────────────────────────────────────────────────────────→
                                                     Reversibility
                                           (Source Code Recovery)
```

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

---

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## ⚡ Quick Reference

```bash
# Encrypt with AES-256 (Method 11)
python Titan Crypt.py
> Select: 1 (Encrypt)
> Enter file: mycode.py
> Select method: 11
> Enter password: your_secure_password

# Decrypt any file
python Titan Crypt.py
> Select: 2 (Decrypt)
> Enter file: mycode_encrypted.py
> Enter password: your_secure_password
```

---

<p align="center">
  <b>TitanCrypt</b> - Protect Your Python Code
  <br>
  <sub>Made with ❤️ by Walter</sub>
  <br><br>
  <a href="https://discord.gg/rgWcEw5G8a">Join Discord</a> •
  <a href="https://github.com/walterwhite-69/Titan-Crypt">GitHub</a>
</p>
