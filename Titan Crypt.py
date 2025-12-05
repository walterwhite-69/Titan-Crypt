#!/usr/bin/env python3
import os
import sys
import base64
import zlib
import lzma
import hashlib
import secrets
import codecs
import re
import struct
import shutil
import time
from datetime import datetime
from typing import Optional, Tuple, List, Dict, Any
from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt, IntPrompt, Confirm
from rich.text import Text
from rich.align import Align
from rich.style import Style
from rich import box
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn, TimeElapsedColumn
from rich.live import Live
from rich.layout import Layout
from rich.spinner import Spinner
from rich.columns import Columns
from Crypto.Cipher import AES, Blowfish, DES3, ChaCha20, Salsa20
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from cryptography.fernet import Fernet, InvalidToken

console = Console()

operation_history = []

def get_terminal_size():
    size = shutil.get_terminal_size((80, 24))
    return size.columns, size.lines

def add_to_history(operation: str, details: str, status: str = "success"):
    operation_history.append({
        "time": datetime.now().strftime("%H:%M:%S"),
        "operation": operation,
        "details": details,
        "status": status
    })
    if len(operation_history) > 10:
        operation_history.pop(0)

def show_history_panel():
    if not operation_history:
        return Panel("[dim]No recent operations[/dim]", title="History", border_style="dim")
    
    history_text = Text()
    for entry in reversed(operation_history[-5:]):
        status_color = "green" if entry["status"] == "success" else "red"
        history_text.append(f"[{entry['time']}] ", style="dim")
        history_text.append(f"{entry['operation']}: ", style="cyan")
        history_text.append(f"{entry['details']}\n", style=status_color)
    
    return Panel(history_text, title="[bold]Recent Activity[/bold]", border_style="blue")

def smooth_transition(message: str = ""):
    console.clear()
    if message:
        with console.status(f"[cyan]{message}[/cyan]", spinner="dots"):
            time.sleep(0.3)

def confirm_action(message: str, title: str = "Confirm") -> bool:
    panel = Panel(
        f"[yellow]{message}[/yellow]",
        title=f"[bold]{title}[/bold]",
        border_style="yellow",
        padding=(1, 2)
    )
    console.print(panel)
    return Confirm.ask("[cyan]Proceed?[/cyan]", default=True)

def show_status_bar():
    width, height = get_terminal_size()
    status = Text()
    status.append(f" TitanCrypt v1.0 ", style="bold white on blue")
    status.append(f" | Terminal: {width}x{height} ", style="dim")
    status.append(f" | Operations: {len(operation_history)} ", style="dim")
    console.print(status)

TITAN_ASCII = r'''
████████╗
╚══██╔══╝
   ██║   
   ██║   
   ██║   
   ╚═╝   
'''

GRADIENT_COLORS = [
    "#FF6B9D", "#FF7B9C", "#FF8A9B", "#FF9A9A", "#FFAA99",
    "#FFB898", "#FFC697", "#FFD496", "#FFE295", "#FFF094",
    "#E8F59B", "#D1FAA2", "#BAFFA9", "#A3FFB0", "#8CFFB7",
    "#75FFBE", "#5EFFC5", "#47FFCC", "#30FFD3", "#19FFDA"
]

def display_rainbow_banner():
    lines = TITAN_ASCII.strip().split('\n')
    rainbow_text = Text()
    
    for i, line in enumerate(lines):
        color_idx = i % len(GRADIENT_COLORS)
        rainbow_text.append(line + "\n", style=GRADIENT_COLORS[color_idx])
    
    console.print(Align.center(rainbow_text))
    console.print(Align.center(Text("TitanCrypt", style="bold cyan")))
    console.print(Align.center(Text("Python Code Encryption & Decryption Tool", style="bold dim")))
    console.print()

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

class EncryptionEngine:
    SIGNATURE = b"TITAN_ENC_V1_"
    
    @staticmethod
    def generate_key(password: str, salt: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        if salt is None:
            salt = get_random_bytes(16)
        key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000, dklen=32)
        return key, salt

    @staticmethod
    def base64_encode(data: bytes) -> bytes:
        return base64.b64encode(data)
    
    @staticmethod
    def base64_decode(data: bytes) -> bytes:
        return base64.b64decode(data)

    @staticmethod
    def rot13(text: str) -> str:
        return codecs.encode(text, 'rot_13')

    @staticmethod
    def xor_encrypt(data: bytes, key: int = 0x5A) -> bytes:
        return bytes([b ^ key for b in data])

    @staticmethod
    def xor_key_encrypt(data: bytes, key: bytes) -> bytes:
        return bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])

    @staticmethod
    def caesar_encrypt(text: str, shift: int = 13) -> str:
        result = []
        for char in text:
            if char.isalpha():
                base = ord('A') if char.isupper() else ord('a')
                result.append(chr((ord(char) - base + shift) % 26 + base))
            else:
                result.append(char)
        return ''.join(result)

    @staticmethod
    def caesar_decrypt(text: str, shift: int = 13) -> str:
        return EncryptionEngine.caesar_encrypt(text, -shift)

    @staticmethod
    def reverse_string(text: str) -> str:
        return text[::-1]

    @staticmethod
    def hex_encode(data: bytes) -> bytes:
        return data.hex().encode()

    @staticmethod
    def hex_decode(data: bytes) -> bytes:
        return bytes.fromhex(data.decode())

    @staticmethod
    def byte_shift(data: bytes, shift: int = 7) -> bytes:
        return bytes([(b + shift) % 256 for b in data])

    @staticmethod
    def byte_unshift(data: bytes, shift: int = 7) -> bytes:
        return bytes([(b - shift) % 256 for b in data])

    @staticmethod
    def substitution_cipher(data: bytes, forward: bool = True) -> bytes:
        table = list(range(256))
        import random
        rng = random.Random(42)
        rng.shuffle(table)
        
        if forward:
            return bytes([table[b] for b in data])
        else:
            reverse_table = [0] * 256
            for i, v in enumerate(table):
                reverse_table[v] = i
            return bytes([reverse_table[b] for b in data])

    @staticmethod
    def aes_encrypt(data: bytes, password: str) -> bytes:
        key, salt = EncryptionEngine.generate_key(password)
        iv = get_random_bytes(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded = pad(data, AES.block_size)
        encrypted = cipher.encrypt(padded)
        return salt + iv + encrypted

    @staticmethod
    def aes_decrypt(data: bytes, password: str) -> bytes:
        salt = data[:16]
        iv = data[16:32]
        encrypted = data[32:]
        key, _ = EncryptionEngine.generate_key(password, salt)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(encrypted)
        return unpad(decrypted, AES.block_size)

    @staticmethod
    def aes_gcm_encrypt(data: bytes, password: str) -> bytes:
        key, salt = EncryptionEngine.generate_key(password)
        cipher = AES.new(key, AES.MODE_GCM)
        encrypted, tag = cipher.encrypt_and_digest(data)
        return salt + cipher.nonce + tag + encrypted

    @staticmethod
    def aes_gcm_decrypt(data: bytes, password: str) -> bytes:
        salt = data[:16]
        nonce = data[16:32]
        tag = data[32:48]
        encrypted = data[48:]
        key, _ = EncryptionEngine.generate_key(password, salt)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(encrypted, tag)

    @staticmethod
    def blowfish_encrypt(data: bytes, password: str) -> bytes:
        key, salt = EncryptionEngine.generate_key(password)
        key = key[:56]
        iv = get_random_bytes(8)
        cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
        padded = pad(data, Blowfish.block_size)
        encrypted = cipher.encrypt(padded)
        return salt + iv + encrypted

    @staticmethod
    def blowfish_decrypt(data: bytes, password: str) -> bytes:
        salt = data[:16]
        iv = data[16:24]
        encrypted = data[24:]
        key, _ = EncryptionEngine.generate_key(password, salt)
        key = key[:56]
        cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
        decrypted = cipher.decrypt(encrypted)
        return unpad(decrypted, Blowfish.block_size)

    @staticmethod
    def des3_encrypt(data: bytes, password: str) -> bytes:
        key, salt = EncryptionEngine.generate_key(password)
        key = key[:24]
        iv = get_random_bytes(8)
        cipher = DES3.new(key, DES3.MODE_CBC, iv)
        padded = pad(data, DES3.block_size)
        encrypted = cipher.encrypt(padded)
        return salt + iv + encrypted

    @staticmethod
    def des3_decrypt(data: bytes, password: str) -> bytes:
        salt = data[:16]
        iv = data[16:24]
        encrypted = data[24:]
        key, _ = EncryptionEngine.generate_key(password, salt)
        key = key[:24]
        cipher = DES3.new(key, DES3.MODE_CBC, iv)
        decrypted = cipher.decrypt(encrypted)
        return unpad(decrypted, DES3.block_size)

    @staticmethod
    def chacha20_encrypt(data: bytes, password: str) -> bytes:
        key, salt = EncryptionEngine.generate_key(password)
        nonce = get_random_bytes(12)
        cipher = ChaCha20.new(key=key, nonce=nonce)
        encrypted = cipher.encrypt(data)
        return salt + nonce + encrypted

    @staticmethod
    def chacha20_decrypt(data: bytes, password: str) -> bytes:
        salt = data[:16]
        nonce = data[16:28]
        encrypted = data[28:]
        key, _ = EncryptionEngine.generate_key(password, salt)
        cipher = ChaCha20.new(key=key, nonce=nonce)
        return cipher.decrypt(encrypted)

    @staticmethod
    def fernet_encrypt(data: bytes, password: str) -> bytes:
        key = base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())
        f = Fernet(key)
        return f.encrypt(data)

    @staticmethod
    def fernet_decrypt(data: bytes, password: str) -> bytes:
        key = base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())
        f = Fernet(key)
        return f.decrypt(data)

    @staticmethod
    def zlib_compress(data: bytes) -> bytes:
        return zlib.compress(data, 9)

    @staticmethod
    def zlib_decompress(data: bytes) -> bytes:
        return zlib.decompress(data)

    @staticmethod
    def lzma_compress(data: bytes) -> bytes:
        return lzma.compress(data)

    @staticmethod
    def lzma_decompress(data: bytes) -> bytes:
        return lzma.decompress(data)

ENCRYPTION_LEVELS = {
    "low": {
        "name": "Low Level",
        "description": "Basic obfuscation - easy to reverse",
        "methods": [
            {"id": 1, "name": "Base64", "desc": "Simple base64 encoding"},
            {"id": 2, "name": "ROT13", "desc": "Letter rotation cipher"},
            {"id": 3, "name": "XOR (0x5A)", "desc": "XOR with fixed key 0x5A"},
            {"id": 4, "name": "Caesar Cipher", "desc": "Shift letters by N positions"},
            {"id": 5, "name": "Reverse", "desc": "Reverse the code string"},
            {"id": 6, "name": "Hex Encode", "desc": "Convert to hexadecimal"},
            {"id": 7, "name": "Byte Shift", "desc": "Shift each byte value"},
            {"id": 8, "name": "Base64 + XOR", "desc": "Base64 then XOR"},
            {"id": 9, "name": "Double Base64", "desc": "Base64 twice"},
            {"id": 10, "name": "Hex + Base64", "desc": "Hex encode then Base64"},
        ]
    },
    "medium": {
        "name": "Medium Level", 
        "description": "Moderate encryption - requires key/password",
        "methods": [
            {"id": 11, "name": "AES-CBC-256", "desc": "AES with CBC mode"},
            {"id": 12, "name": "AES-GCM-256", "desc": "AES with authenticated encryption"},
            {"id": 13, "name": "Blowfish", "desc": "Blowfish block cipher"},
            {"id": 14, "name": "3DES", "desc": "Triple DES encryption"},
            {"id": 15, "name": "ChaCha20", "desc": "ChaCha20 stream cipher"},
            {"id": 16, "name": "Fernet", "desc": "Fernet symmetric encryption"},
            {"id": 17, "name": "XOR + AES", "desc": "XOR then AES encrypt"},
            {"id": 18, "name": "Substitution Cipher", "desc": "Byte substitution table"},
            {"id": 19, "name": "Compressed AES", "desc": "Zlib + AES"},
            {"id": 20, "name": "Fernet + Base64", "desc": "Fernet then Base64"},
        ]
    },
    "high": {
        "name": "High Level",
        "description": "Strong encryption - multi-layer protection",
        "methods": [
            {"id": 21, "name": "AES + Blowfish", "desc": "Dual cipher encryption"},
            {"id": 22, "name": "Zlib + AES + Base64", "desc": "Compress, encrypt, encode"},
            {"id": 23, "name": "LZMA + ChaCha20", "desc": "LZMA compression + ChaCha"},
            {"id": 24, "name": "Triple Layer", "desc": "XOR + AES + Fernet"},
            {"id": 25, "name": "Substitution + AES", "desc": "Custom cipher + AES"},
            {"id": 26, "name": "Compressed Fernet", "desc": "LZMA + Fernet"},
            {"id": 27, "name": "AES-GCM + Blowfish", "desc": "Dual authenticated"},
            {"id": 28, "name": "Reverse + AES + Hex", "desc": "Multi-transform"},
            {"id": 29, "name": "XOR Chain + AES", "desc": "Multi-key XOR + AES"},
            {"id": 30, "name": "Marshal + AES", "desc": "Marshal bytecode + AES"},
        ]
    },
    "ultra": {
        "name": "Ultra Level",
        "description": "Maximum security - extreme obfuscation",
        "methods": [
            {"id": 31, "name": "4-Layer Beast", "desc": "Base64→XOR→AES→Substitution→Zlib"},
            {"id": 32, "name": "Fortress", "desc": "LZMA→AES-GCM→Blowfish→Base64"},
            {"id": 33, "name": "Phantom", "desc": "Marshal→ChaCha20→LZMA→XOR→B64"},
            {"id": 34, "name": "Shadow", "desc": "Fernet→AES→3DES→Zlib→Hex"},
            {"id": 35, "name": "Hydra", "desc": "5 encryption layers"},
            {"id": 36, "name": "Cerberus", "desc": "Triple AES with different keys"},
            {"id": 37, "name": "Chimera", "desc": "Random layer order"},
            {"id": 38, "name": "Leviathan", "desc": "All compressions + All ciphers"},
            {"id": 39, "name": "Dragon", "desc": "Maximum obfuscation"},
            {"id": 40, "name": "Titan", "desc": "Ultimate protection"},
        ]
    }
}

class TitanEncryptor:
    def __init__(self):
        self.engine = EncryptionEngine()
        
    def create_loader(self, encrypted_data: bytes, method_id: int, password: Optional[str] = None) -> str:
        b64_data = base64.b64encode(encrypted_data).decode()
        
        loader = f'''# Encrypted with TitanCrypt v2.0 - Method {method_id}
import base64
import zlib
import lzma
import hashlib
import codecs
from Crypto.Cipher import AES, Blowfish, DES3, ChaCha20
from Crypto.Util.Padding import unpad
from cryptography.fernet import Fernet

_d = "{b64_data}"
_m = {method_id}
_p = "{password or ''}"

def _decrypt():
    data = base64.b64decode(_d)
    # Decryption logic embedded
    return _run_decrypt(data, _m, _p)

def _run_decrypt(data, method, pwd):
    # Method-specific decryption
    return data

exec(compile(_decrypt().decode(), '<titan>', 'exec'))
'''
        return loader
        
    def encrypt(self, code: str, method_id: int, password: Optional[str] = None) -> Tuple[bytes, dict]:
        data = code.encode('utf-8')
        metadata = {"method": method_id, "has_password": password is not None}
        
        if method_id == 1:
            result = self.engine.base64_encode(data)
        elif method_id == 2:
            result = self.engine.rot13(code).encode()
        elif method_id == 3:
            result = self.engine.xor_encrypt(data)
        elif method_id == 4:
            result = self.engine.caesar_encrypt(code, 13).encode()
        elif method_id == 5:
            result = self.engine.reverse_string(code).encode()
        elif method_id == 6:
            result = self.engine.hex_encode(data)
        elif method_id == 7:
            result = self.engine.byte_shift(data)
        elif method_id == 8:
            result = self.engine.xor_encrypt(self.engine.base64_encode(data))
        elif method_id == 9:
            result = self.engine.base64_encode(self.engine.base64_encode(data))
        elif method_id == 10:
            result = self.engine.base64_encode(self.engine.hex_encode(data))
        elif method_id == 11:
            result = self.engine.aes_encrypt(data, password)
        elif method_id == 12:
            result = self.engine.aes_gcm_encrypt(data, password)
        elif method_id == 13:
            result = self.engine.blowfish_encrypt(data, password)
        elif method_id == 14:
            result = self.engine.des3_encrypt(data, password)
        elif method_id == 15:
            result = self.engine.chacha20_encrypt(data, password)
        elif method_id == 16:
            result = self.engine.fernet_encrypt(data, password)
        elif method_id == 17:
            xored = self.engine.xor_encrypt(data)
            result = self.engine.aes_encrypt(xored, password)
        elif method_id == 18:
            result = self.engine.substitution_cipher(data)
        elif method_id == 19:
            compressed = self.engine.zlib_compress(data)
            result = self.engine.aes_encrypt(compressed, password)
        elif method_id == 20:
            encrypted = self.engine.fernet_encrypt(data, password)
            result = self.engine.base64_encode(encrypted)
        elif method_id == 21:
            aes_encrypted = self.engine.aes_encrypt(data, password)
            result = self.engine.blowfish_encrypt(aes_encrypted, password + "_bf")
        elif method_id == 22:
            compressed = self.engine.zlib_compress(data)
            aes_encrypted = self.engine.aes_encrypt(compressed, password)
            result = self.engine.base64_encode(aes_encrypted)
        elif method_id == 23:
            compressed = self.engine.lzma_compress(data)
            result = self.engine.chacha20_encrypt(compressed, password)
        elif method_id == 24:
            xored = self.engine.xor_encrypt(data)
            aes_encrypted = self.engine.aes_encrypt(xored, password)
            result = self.engine.fernet_encrypt(aes_encrypted, password + "_fernet")
        elif method_id == 25:
            subst = self.engine.substitution_cipher(data)
            result = self.engine.aes_encrypt(subst, password)
        elif method_id == 26:
            compressed = self.engine.lzma_compress(data)
            result = self.engine.fernet_encrypt(compressed, password)
        elif method_id == 27:
            aes_encrypted = self.engine.aes_gcm_encrypt(data, password)
            result = self.engine.blowfish_encrypt(aes_encrypted, password + "_bf")
        elif method_id == 28:
            reversed_data = self.engine.reverse_string(code).encode()
            aes_encrypted = self.engine.aes_encrypt(reversed_data, password)
            result = self.engine.hex_encode(aes_encrypted)
        elif method_id == 29:
            xor1 = self.engine.xor_encrypt(data, 0x5A)
            xor2 = self.engine.xor_encrypt(xor1, 0xA5)
            result = self.engine.aes_encrypt(xor2, password)
        elif method_id == 30:
            import marshal
            code_obj = compile(code, '<titan>', 'exec')
            marshaled = marshal.dumps(code_obj)
            result = self.engine.aes_encrypt(marshaled, password)
            metadata["is_marshal"] = True
        elif method_id == 31:
            b64 = self.engine.base64_encode(data)
            xored = self.engine.xor_encrypt(b64, 0x5A)
            aes = self.engine.aes_encrypt(xored, password)
            subst = self.engine.substitution_cipher(aes)
            result = self.engine.zlib_compress(subst)
        elif method_id == 32:
            compressed = self.engine.lzma_compress(data)
            aes = self.engine.aes_gcm_encrypt(compressed, password)
            bf = self.engine.blowfish_encrypt(aes, password + "_bf")
            result = self.engine.base64_encode(bf)
        elif method_id == 33:
            import marshal
            code_obj = compile(code, '<titan>', 'exec')
            marshaled = marshal.dumps(code_obj)
            chacha = self.engine.chacha20_encrypt(marshaled, password)
            compressed = self.engine.lzma_compress(chacha)
            xored = self.engine.xor_encrypt(compressed, 0xAA)
            result = self.engine.base64_encode(xored)
            metadata["is_marshal"] = True
        elif method_id == 34:
            fernet = self.engine.fernet_encrypt(data, password)
            aes = self.engine.aes_encrypt(fernet, password + "_aes")
            des3 = self.engine.des3_encrypt(aes, password + "_des")
            compressed = self.engine.zlib_compress(des3)
            result = self.engine.hex_encode(compressed)
        elif method_id == 35:
            layer1 = self.engine.xor_encrypt(data, 0x11)
            layer2 = self.engine.aes_encrypt(layer1, password)
            layer3 = self.engine.blowfish_encrypt(layer2, password + "_2")
            layer4 = self.engine.chacha20_encrypt(layer3, password + "_3")
            layer5 = self.engine.fernet_encrypt(layer4, password + "_4")
            result = layer5
        elif method_id == 36:
            aes1 = self.engine.aes_encrypt(data, password + "_1")
            aes2 = self.engine.aes_encrypt(aes1, password + "_2")
            aes3 = self.engine.aes_encrypt(aes2, password + "_3")
            result = aes3
        elif method_id == 37:
            import random
            seed_val = int(hashlib.md5(password.encode()).hexdigest(), 16) % (2**32)
            random.seed(seed_val)
            layers = [
                lambda d: self.engine.xor_encrypt(d, 0x42),
                lambda d: self.engine.base64_encode(d),
                lambda d: self.engine.aes_encrypt(d, password),
                lambda d: self.engine.zlib_compress(d),
            ]
            random.shuffle(layers)
            result = data
            for layer in layers:
                result = layer(result)
            metadata["layer_order"] = [l.__name__ if hasattr(l, '__name__') else str(i) for i, l in enumerate(layers)]
        elif method_id == 38:
            compressed1 = self.engine.zlib_compress(data)
            compressed2 = self.engine.lzma_compress(compressed1)
            aes = self.engine.aes_encrypt(compressed2, password)
            bf = self.engine.blowfish_encrypt(aes, password + "_bf")
            chacha = self.engine.chacha20_encrypt(bf, password + "_ch")
            fernet = self.engine.fernet_encrypt(chacha, password + "_fn")
            result = self.engine.base64_encode(fernet)
        elif method_id == 39:
            import marshal
            code_obj = compile(code, '<titan>', 'exec')
            marshaled = marshal.dumps(code_obj)
            compressed = self.engine.lzma_compress(marshaled)
            xored = self.engine.xor_encrypt(compressed, 0xFF)
            subst = self.engine.substitution_cipher(xored)
            aes = self.engine.aes_gcm_encrypt(subst, password)
            bf = self.engine.blowfish_encrypt(aes, password + "_bf")
            b64 = self.engine.base64_encode(bf)
            result = self.engine.zlib_compress(b64)
            metadata["is_marshal"] = True
        elif method_id == 40:
            import marshal
            code_obj = compile(code, '<titan>', 'exec')
            marshaled = marshal.dumps(code_obj)
            layer1 = self.engine.lzma_compress(marshaled)
            layer2 = self.engine.xor_encrypt(layer1, 0xDE)
            layer3 = self.engine.substitution_cipher(layer2)
            layer4 = self.engine.aes_gcm_encrypt(layer3, password)
            layer5 = self.engine.blowfish_encrypt(layer4, password + "_l5")
            layer6 = self.engine.chacha20_encrypt(layer5, password + "_l6")
            layer7 = self.engine.fernet_encrypt(layer6, password + "_l7")
            layer8 = self.engine.zlib_compress(layer7)
            layer9 = self.engine.base64_encode(layer8)
            layer10 = self.engine.xor_encrypt(layer9, 0xAD)
            result = layer10
            metadata["is_marshal"] = True
        else:
            result = data
            
        header = struct.pack("<13sHH", EncryptionEngine.SIGNATURE, method_id, len(password or ""))
        if password:
            header += password.encode()[:255]
        
        final = header + result
        return final, metadata

class UniversalDecoder:
    PYTHON_SIGNATURES = [
        b'import ', b'from ', b'def ', b'class ', b'if __name__', 
        b'print(', b'print ', b'#!/usr/bin', b'# -*-', b'#!python',
        b'async def', b'await ', b'lambda ', b'return ', b'yield ',
        b'try:', b'except:', b'finally:', b'with ', b'while ',
        b'for ', b'elif ', b'else:', b'pass', b'break', b'continue',
        b'global ', b'nonlocal ', b'assert ', b'raise ', b'del ',
        b'@', b'"""', b"'''"
    ]
    
    COMPRESSION_MAGIC = {
        b'\x78\x9c': 'zlib',
        b'\x78\x01': 'zlib_low',
        b'\x78\xda': 'zlib_high',
        b'\x1f\x8b': 'gzip',
        b'\xfd7zXZ': 'lzma',
        b'\x5d\x00': 'lzma_raw',
    }
    
    MARSHAL_MAGIC = [b'\xe3\x00', b'\xe3\x01', b'\xe3\x02', b'\xe3\x03']
    
    def __init__(self):
        self.engine = EncryptionEngine()
        self.layers_detected = []
        self.max_depth = 50
        
    def _calculate_entropy(self, data: bytes) -> float:
        if not data:
            return 0.0
        freq = {}
        for b in data:
            freq[b] = freq.get(b, 0) + 1
        entropy = 0.0
        for count in freq.values():
            p = count / len(data)
            if p > 0:
                import math
                entropy -= p * math.log2(p)
        return entropy
    
    def _printable_ratio(self, data: bytes) -> float:
        if not data:
            return 0.0
        printable = sum(1 for b in data if 32 <= b <= 126 or b in (9, 10, 13))
        return printable / len(data)
    
    def _is_python_code(self, data: bytes) -> bool:
        try:
            text = data.decode('utf-8', errors='strict')
            for sig in self.PYTHON_SIGNATURES:
                if sig in data:
                    return True
            if self._printable_ratio(data) > 0.85:
                if any(kw in text for kw in ['import', 'def ', 'class ', 'print', '=']):
                    return True
        except:
            pass
        return False
    
    def _detect_base64(self, data: bytes) -> Tuple[bool, float]:
        try:
            text = data.decode('utf-8', errors='strict').strip()
            if len(text) < 4:
                return False, 0.0
            if not re.match(r'^[A-Za-z0-9+/=\s]+$', text):
                return False, 0.0
            clean = text.replace('\n', '').replace('\r', '').replace(' ', '')
            if len(clean) % 4 != 0:
                return False, 0.0
            decoded = base64.b64decode(clean)
            if len(decoded) > 0:
                confidence = 0.9 if len(clean) > 20 else 0.7
                return True, confidence
        except:
            pass
        return False, 0.0
    
    def _detect_hex(self, data: bytes) -> Tuple[bool, float]:
        try:
            text = data.decode('utf-8', errors='strict').strip()
            if len(text) < 2 or len(text) % 2 != 0:
                return False, 0.0
            if all(c in '0123456789abcdefABCDEF' for c in text):
                confidence = 0.85 if len(text) > 10 else 0.6
                return True, confidence
        except:
            pass
        return False, 0.0
    
    def _detect_compression(self, data: bytes) -> Tuple[str, float]:
        if len(data) < 2:
            return None, 0.0
        for magic, comp_type in self.COMPRESSION_MAGIC.items():
            if data.startswith(magic):
                return comp_type, 0.95
        if len(data) > 5 and data[0:1] == b'\x5d':
            return 'lzma_raw', 0.7
        return None, 0.0
    
    def _detect_xor_key(self, data: bytes) -> Tuple[int, float]:
        if len(data) < 10:
            return None, 0.0
        best_key = None
        best_score = 0.0
        common_keys = [0x00, 0x5A, 0xA5, 0xFF, 0xAA, 0x55, 0xDE, 0xAD, 0x42, 0x11, 0x22, 0x33]
        for key in common_keys:
            decoded = bytes([b ^ key for b in data[:200]])
            printable = self._printable_ratio(decoded)
            if printable > best_score and printable > 0.6:
                best_score = printable
                best_key = key
        if best_key is None:
            for key in range(256):
                if key in common_keys:
                    continue
                decoded = bytes([b ^ key for b in data[:100]])
                printable = self._printable_ratio(decoded)
                if printable > best_score and printable > 0.7:
                    best_score = printable
                    best_key = key
        if best_key is not None:
            return best_key, best_score * 0.8
        return None, 0.0
    
    def _detect_rot13(self, data: bytes) -> Tuple[bool, float]:
        try:
            text = data.decode('utf-8', errors='strict')
            if not text.isascii():
                return False, 0.0
            decoded = codecs.decode(text, 'rot_13')
            for sig in ['import', 'def ', 'class ', 'print']:
                if sig in decoded and sig not in text:
                    return True, 0.85
        except:
            pass
        return False, 0.0
    
    def _detect_marshal(self, data: bytes) -> Tuple[bool, float]:
        if len(data) < 4:
            return False, 0.0
        for magic in self.MARSHAL_MAGIC:
            if data.startswith(magic):
                return True, 0.9
        return False, 0.0
    
    def _detect_fernet(self, data: bytes) -> Tuple[bool, float]:
        try:
            text = data.decode('utf-8', errors='strict')
            if text.startswith('gAAA') and len(text) > 50:
                return True, 0.9
        except:
            pass
        return False, 0.0
    
    def _detect_titan(self, data: bytes) -> Tuple[int, float]:
        if data.startswith(EncryptionEngine.SIGNATURE):
            try:
                method_id = struct.unpack("<H", data[13:15])[0]
                return method_id, 1.0
            except:
                pass
        try:
            decoded = base64.b64decode(data)
            if decoded.startswith(EncryptionEngine.SIGNATURE):
                return -2, 0.95
        except:
            pass
        return None, 0.0
    
    def _detect_substitution(self, data: bytes) -> Tuple[bool, float]:
        if len(data) < 20:
            return False, 0.0
        entropy = self._calculate_entropy(data)
        if 7.0 < entropy < 8.0:
            unique_bytes = len(set(data))
            if unique_bytes > 200:
                return True, 0.5
        return False, 0.0
    
    def _detect_exec_payload(self, data: bytes) -> Tuple[bytes, float]:
        try:
            text = data.decode('utf-8', errors='ignore')
            patterns = [
                r'exec\s*\(\s*["\'](.+?)["\']\s*\)',
                r'exec\s*\(\s*compile\s*\(',
                r'eval\s*\(\s*["\'](.+?)["\']\s*\)',
                r'exec\s*\(\s*__import__',
                r'_d\s*=\s*["\']([A-Za-z0-9+/=]+)["\']',
                r'b64decode\s*\(\s*["\']([A-Za-z0-9+/=]+)["\']',
            ]
            for pattern in patterns:
                match = re.search(pattern, text, re.DOTALL)
                if match:
                    return match.group(1).encode() if match.lastindex else data, 0.8
        except:
            pass
        return None, 0.0
    
    def _detect_obfuscation_patterns(self, data: bytes) -> Dict[str, Any]:
        patterns_found = []
        try:
            text = data.decode('utf-8', errors='ignore')
            
            b64_matches = re.findall(r'b64decode\s*\(\s*[\'"]([A-Za-z0-9+/=]{50,})[\'"]', text)
            if b64_matches:
                patterns_found.append({
                    'type': 'embedded_base64',
                    'count': len(b64_matches),
                    'total_size': sum(len(m) for m in b64_matches)
                })
            
            hex_matches = re.findall(r'fromhex\s*\(\s*[\'"]([0-9a-fA-F]{20,})[\'"]', text)
            if hex_matches:
                patterns_found.append({
                    'type': 'embedded_hex',
                    'count': len(hex_matches),
                    'total_size': sum(len(m) for m in hex_matches)
                })
            
            exec_count = len(re.findall(r'\bexec\s*\(', text))
            eval_count = len(re.findall(r'\beval\s*\(', text))
            if exec_count or eval_count:
                patterns_found.append({
                    'type': 'exec_eval',
                    'exec_count': exec_count,
                    'eval_count': eval_count
                })
            
            compile_matches = re.findall(r'compile\s*\([^)]+[\'"]exec[\'"]', text)
            if compile_matches:
                patterns_found.append({
                    'type': 'dynamic_compile',
                    'count': len(compile_matches)
                })
            
            long_vars = re.findall(r'\b([A-Za-z_][A-Za-z0-9_]{30,})\b', text)
            unique_long = set(long_vars)
            if len(unique_long) > 5:
                patterns_found.append({
                    'type': 'obfuscated_names',
                    'count': len(unique_long),
                    'sample': list(unique_long)[:3]
                })
            
            marshal_usage = 'marshal.loads' in text or 'marshal.dumps' in text
            if marshal_usage:
                patterns_found.append({
                    'type': 'marshal_usage',
                    'detected': True
                })
            
            aes_usage = 'AES' in text or 'Cipher' in text or 'encrypt' in text.lower()
            if aes_usage:
                patterns_found.append({
                    'type': 'crypto_usage',
                    'detected': True
                })
            
            zlib_usage = 'zlib.decompress' in text or 'decompress(' in text
            if zlib_usage:
                patterns_found.append({
                    'type': 'compression_usage',
                    'detected': True
                })
            
            xor_patterns = re.findall(r'\^', text)
            if len(xor_patterns) > 10:
                patterns_found.append({
                    'type': 'xor_operations',
                    'count': len(xor_patterns)
                })
            
            substitution = re.findall(r'list\s*\(\s*range\s*\(\s*256\s*\)\s*\)', text)
            if substitution:
                patterns_found.append({
                    'type': 'substitution_table',
                    'count': len(substitution)
                })
                
        except:
            pass
        
        return {
            'is_obfuscated': len(patterns_found) > 0,
            'patterns': patterns_found,
            'obfuscation_score': min(len(patterns_found) * 15, 100)
        }
    
    def _extract_embedded_payload(self, data: bytes) -> Tuple[bytes, str, float]:
        try:
            text = data.decode('utf-8', errors='ignore')
            
            loader_pattern = r'_(?:d|DATA)\s*=\s*["\']([A-Za-z0-9+/=]{50,})["\']'
            match = re.search(loader_pattern, text)
            if match:
                try:
                    decoded = base64.b64decode(match.group(1))
                    if decoded.startswith(b'TITAN_ENC'):
                        return decoded, 'titan_loader', 0.95
                except:
                    pass
            
            b64_pattern = r'b64decode\s*\(\s*[\'"]([A-Za-z0-9+/=]{100,})[\'"]'
            matches = re.findall(b64_pattern, text)
            if matches:
                longest = max(matches, key=len)
                try:
                    decoded = base64.b64decode(longest)
                    return decoded, 'extracted_base64', 0.9
                except:
                    pass
            
            var_pattern = r'["\']([A-Za-z0-9+/=]{200,})["\']'
            matches = re.findall(var_pattern, text)
            if matches:
                longest = max(matches, key=len)
                try:
                    decoded = base64.b64decode(longest)
                    return decoded, 'extracted_base64_var', 0.85
                except:
                    pass
                    
        except:
            pass
        return None, None, 0.0
    
    def _apply_transform(self, data: bytes, transform_type: str, params: dict = None) -> bytes:
        params = params or {}
        try:
            if transform_type == 'base64':
                text = data.decode('utf-8', errors='strict').strip()
                clean = text.replace('\n', '').replace('\r', '').replace(' ', '')
                return base64.b64decode(clean)
            elif transform_type == 'hex':
                text = data.decode('utf-8', errors='strict').strip()
                return bytes.fromhex(text)
            elif transform_type == 'zlib' or transform_type.startswith('zlib'):
                return zlib.decompress(data)
            elif transform_type == 'gzip':
                import gzip
                return gzip.decompress(data)
            elif transform_type == 'lzma' or transform_type == 'lzma_raw':
                return lzma.decompress(data)
            elif transform_type == 'xor':
                key = params.get('key', 0x5A)
                return bytes([b ^ key for b in data])
            elif transform_type == 'rot13':
                text = data.decode('utf-8')
                return codecs.decode(text, 'rot_13').encode()
            elif transform_type == 'marshal':
                import marshal
                return marshal.loads(data)
            elif transform_type == 'substitution':
                return self.engine.substitution_cipher(data, forward=False)
            elif transform_type == 'reverse':
                return data[::-1]
            elif transform_type == 'titan':
                method_id = params.get('method_id')
                password = params.get('password')
                if method_id == -2:
                    data = base64.b64decode(data)
                if data.startswith(EncryptionEngine.SIGNATURE):
                    pwd_len = struct.unpack("<H", data[15:17])[0]
                    stored_pwd = data[17:17+pwd_len].decode() if pwd_len > 0 else None
                    encrypted_data = data[17+pwd_len:]
                    if pwd_len > 0 and not password:
                        password = stored_pwd
                    decryptor = TitanDecryptor()
                    return decryptor._decrypt_by_method(encrypted_data, method_id if method_id > 0 else struct.unpack("<H", data[13:15])[0], password)
        except Exception as e:
            pass
        return None
    
    def analyze(self, data: bytes, password: str = None) -> Dict[str, Any]:
        self.layers_detected = []
        current_data = data
        depth = 0
        obfuscation_info = None
        
        if self._is_python_code(data):
            obfuscation_info = self._detect_obfuscation_patterns(data)
            if obfuscation_info['is_obfuscated']:
                extracted, extract_type, extract_conf = self._extract_embedded_payload(data)
                if extracted and extract_conf > 0.5:
                    self.layers_detected.append({
                        'layer': 1,
                        'type': 'python_obfuscation',
                        'confidence': obfuscation_info['obfuscation_score'],
                        'size_before': len(data),
                        'size_after': len(extracted),
                        'patterns': [p['type'] for p in obfuscation_info['patterns']]
                    })
                    current_data = extracted
                    depth = 1
        
        while depth < self.max_depth:
            if self._is_python_code(current_data) and depth > 0:
                break
            
            best_transform = None
            best_confidence = 0.0
            best_params = {}
            
            titan_id, titan_conf = self._detect_titan(current_data)
            if titan_conf > best_confidence:
                best_transform = 'titan'
                best_confidence = titan_conf
                best_params = {'method_id': titan_id, 'password': password}
            
            is_b64, b64_conf = self._detect_base64(current_data)
            if b64_conf > best_confidence:
                best_transform = 'base64'
                best_confidence = b64_conf
            
            is_hex, hex_conf = self._detect_hex(current_data)
            if hex_conf > best_confidence:
                best_transform = 'hex'
                best_confidence = hex_conf
            
            comp_type, comp_conf = self._detect_compression(current_data)
            if comp_conf > best_confidence:
                best_transform = comp_type
                best_confidence = comp_conf
            
            xor_key, xor_conf = self._detect_xor_key(current_data)
            if xor_conf > best_confidence:
                best_transform = 'xor'
                best_confidence = xor_conf
                best_params = {'key': xor_key}
            
            is_rot13, rot_conf = self._detect_rot13(current_data)
            if rot_conf > best_confidence:
                best_transform = 'rot13'
                best_confidence = rot_conf
            
            is_marshal, marsh_conf = self._detect_marshal(current_data)
            if marsh_conf > best_confidence:
                best_transform = 'marshal'
                best_confidence = marsh_conf
            
            is_fernet, fernet_conf = self._detect_fernet(current_data)
            if fernet_conf > best_confidence and password:
                best_transform = 'fernet'
                best_confidence = fernet_conf
                best_params = {'password': password}
            
            if best_confidence < 0.5:
                break
            
            new_data = self._apply_transform(current_data, best_transform, best_params)
            if new_data is None or new_data == current_data:
                break
            
            layer_info = {
                'layer': depth + 1,
                'type': best_transform,
                'confidence': round(best_confidence * 100, 1),
                'size_before': len(current_data),
                'size_after': len(new_data)
            }
            if best_params:
                layer_info['params'] = {k: v for k, v in best_params.items() if k != 'password'}
            
            self.layers_detected.append(layer_info)
            current_data = new_data
            depth += 1
        
        is_plaintext = self._is_python_code(current_data)
        
        if obfuscation_info is None and self._is_python_code(data):
            obfuscation_info = self._detect_obfuscation_patterns(data)
        
        result = {
            'total_layers': len(self.layers_detected),
            'layers': self.layers_detected,
            'is_plaintext': is_plaintext,
            'final_size': len(current_data),
            'printable_ratio': round(self._printable_ratio(current_data) * 100, 1),
            'decrypted_data': current_data
        }
        
        if obfuscation_info:
            result['obfuscation'] = obfuscation_info
        
        return result
    
    def decode(self, data: bytes, password: str = None) -> Tuple[bytes, Dict[str, Any]]:
        result = self.analyze(data, password)
        return result['decrypted_data'], result


class TitanDecryptor:
    def __init__(self):
        self.engine = EncryptionEngine()
        
    def detect_encryption(self, data: bytes) -> Tuple[int, str, Dict[str, Any]]:
        universal = UniversalDecoder()
        analysis = universal.analyze(data)
        
        if data.startswith(EncryptionEngine.SIGNATURE):
            try:
                method_id = struct.unpack("<H", data[13:15])[0]
                method_name = self._get_method_name(method_id)
                return method_id, f"TitanCrypt encrypted [{method_name}]", analysis
            except:
                pass
        
        try:
            decoded = base64.b64decode(data)
            if decoded.startswith(EncryptionEngine.SIGNATURE):
                return -2, "Base64 wrapped TitanCrypt file", analysis
        except:
            pass
        
        if analysis['total_layers'] > 0:
            layer_types = [l['type'] for l in analysis['layers']]
            return -1, f"Detected {analysis['total_layers']} layers: {' → '.join(layer_types)}", analysis
            
        if self._is_valid_utf8(data):
            text = data.decode('utf-8', errors='ignore')
            if all(c in '0123456789abcdefABCDEF' for c in text.strip()):
                return 6, "Hex encoded", analysis
            if re.match(r'^[A-Za-z0-9+/=]+$', text.strip()) and len(text) % 4 == 0:
                return 1, "Base64 encoded", analysis
        
        return 0, "Unknown format", analysis
    
    def _get_method_name(self, method_id: int) -> str:
        for level_data in ENCRYPTION_LEVELS.values():
            for method in level_data['methods']:
                if method['id'] == method_id:
                    return method['name']
        return f"Method {method_id}"
    
    def _is_valid_utf8(self, data: bytes) -> bool:
        try:
            data.decode('utf-8')
            return True
        except:
            return False
    
    def decrypt(self, data: bytes, password: str = None) -> Tuple[bytes, dict]:
        metadata = {}
        
        if data.startswith(EncryptionEngine.SIGNATURE):
            method_id = struct.unpack("<H", data[13:15])[0]
            pwd_len = struct.unpack("<H", data[15:17])[0]
            stored_pwd = data[17:17+pwd_len].decode() if pwd_len > 0 else None
            encrypted_data = data[17+pwd_len:]
            
            if pwd_len > 0 and not password:
                password = stored_pwd
            
            metadata["method"] = method_id
            metadata["method_name"] = self._get_method_name(method_id)
            return self._decrypt_by_method(encrypted_data, method_id, password), metadata
        
        try:
            text = data.decode('utf-8', errors='ignore')
            if '_DATA=' in text or '_DATA =' in text:
                data_match = re.search(r'_DATA\s*=\s*["\']([A-Za-z0-9+/=]+)["\']', text)
                method_match = re.search(r'_METHOD\s*=\s*(\d+)', text)
                marshal_match = re.search(r'_MARSHAL\s*=\s*(True|False)', text)
                
                if data_match and method_match:
                    encoded_data = data_match.group(1)
                    method_id = int(method_match.group(1))
                    is_marshal = marshal_match and marshal_match.group(1) == 'True'
                    
                    raw_encrypted = base64.b64decode(encoded_data)
                    
                    if raw_encrypted.startswith(EncryptionEngine.SIGNATURE):
                        pwd_len = struct.unpack("<H", raw_encrypted[15:17])[0]
                        stored_pwd = raw_encrypted[17:17+pwd_len].decode() if pwd_len > 0 else None
                        encrypted_data = raw_encrypted[17+pwd_len:]
                        
                        if pwd_len > 0 and not password:
                            password = stored_pwd
                        
                        metadata["method"] = method_id
                        metadata["method_name"] = self._get_method_name(method_id)
                        metadata["is_marshal"] = is_marshal
                        metadata["loader_detected"] = True
                        
                        decrypted = self._decrypt_by_method(encrypted_data, method_id, password)
                        
                        if is_marshal and decrypted:
                            try:
                                import marshal as marshal_mod
                                code_obj = marshal_mod.loads(decrypted)
                                metadata["marshal_loaded"] = True
                            except:
                                pass
                        
                        return decrypted, metadata
        except Exception as e:
            pass
        
        universal = UniversalDecoder()
        decrypted, analysis = universal.decode(data, password)
        metadata["layers"] = analysis['total_layers']
        metadata["layer_details"] = analysis['layers']
        metadata["is_plaintext"] = analysis['is_plaintext']
        return decrypted, metadata
    
    def _decrypt_by_method(self, data: bytes, method_id: int, password: str) -> bytes:
        if method_id == 1:
            return self.engine.base64_decode(data)
        elif method_id == 2:
            return self.engine.rot13(data.decode()).encode()
        elif method_id == 3:
            return self.engine.xor_encrypt(data)
        elif method_id == 4:
            return self.engine.caesar_decrypt(data.decode(), 13).encode()
        elif method_id == 5:
            return self.engine.reverse_string(data.decode()).encode()
        elif method_id == 6:
            return self.engine.hex_decode(data)
        elif method_id == 7:
            return self.engine.byte_unshift(data)
        elif method_id == 8:
            return self.engine.base64_decode(self.engine.xor_encrypt(data))
        elif method_id == 9:
            return self.engine.base64_decode(self.engine.base64_decode(data))
        elif method_id == 10:
            return self.engine.hex_decode(self.engine.base64_decode(data))
        elif method_id == 11:
            return self.engine.aes_decrypt(data, password)
        elif method_id == 12:
            return self.engine.aes_gcm_decrypt(data, password)
        elif method_id == 13:
            return self.engine.blowfish_decrypt(data, password)
        elif method_id == 14:
            return self.engine.des3_decrypt(data, password)
        elif method_id == 15:
            return self.engine.chacha20_decrypt(data, password)
        elif method_id == 16:
            return self.engine.fernet_decrypt(data, password)
        elif method_id == 17:
            aes_decrypted = self.engine.aes_decrypt(data, password)
            return self.engine.xor_encrypt(aes_decrypted)
        elif method_id == 18:
            return self.engine.substitution_cipher(data, forward=False)
        elif method_id == 19:
            aes_decrypted = self.engine.aes_decrypt(data, password)
            return self.engine.zlib_decompress(aes_decrypted)
        elif method_id == 20:
            decoded = self.engine.base64_decode(data)
            return self.engine.fernet_decrypt(decoded, password)
        elif method_id == 21:
            bf_decrypted = self.engine.blowfish_decrypt(data, password + "_bf")
            return self.engine.aes_decrypt(bf_decrypted, password)
        elif method_id == 22:
            decoded = self.engine.base64_decode(data)
            aes_decrypted = self.engine.aes_decrypt(decoded, password)
            return self.engine.zlib_decompress(aes_decrypted)
        elif method_id == 23:
            chacha_decrypted = self.engine.chacha20_decrypt(data, password)
            return self.engine.lzma_decompress(chacha_decrypted)
        elif method_id == 24:
            fernet_decrypted = self.engine.fernet_decrypt(data, password + "_fernet")
            aes_decrypted = self.engine.aes_decrypt(fernet_decrypted, password)
            return self.engine.xor_encrypt(aes_decrypted)
        elif method_id == 25:
            aes_decrypted = self.engine.aes_decrypt(data, password)
            return self.engine.substitution_cipher(aes_decrypted, forward=False)
        elif method_id == 26:
            fernet_decrypted = self.engine.fernet_decrypt(data, password)
            return self.engine.lzma_decompress(fernet_decrypted)
        elif method_id == 27:
            bf_decrypted = self.engine.blowfish_decrypt(data, password + "_bf")
            return self.engine.aes_gcm_decrypt(bf_decrypted, password)
        elif method_id == 28:
            hex_decoded = self.engine.hex_decode(data)
            aes_decrypted = self.engine.aes_decrypt(hex_decoded, password)
            return self.engine.reverse_string(aes_decrypted.decode()).encode()
        elif method_id == 29:
            aes_decrypted = self.engine.aes_decrypt(data, password)
            xor1 = self.engine.xor_encrypt(aes_decrypted, 0xA5)
            return self.engine.xor_encrypt(xor1, 0x5A)
        elif method_id == 30:
            import marshal
            decrypted = self.engine.aes_decrypt(data, password)
            return decrypted
        elif method_id == 31:
            decompressed = self.engine.zlib_decompress(data)
            unsubst = self.engine.substitution_cipher(decompressed, forward=False)
            aes_decrypted = self.engine.aes_decrypt(unsubst, password)
            unxored = self.engine.xor_encrypt(aes_decrypted, 0x5A)
            return self.engine.base64_decode(unxored)
        elif method_id == 32:
            decoded = self.engine.base64_decode(data)
            bf_decrypted = self.engine.blowfish_decrypt(decoded, password + "_bf")
            aes_decrypted = self.engine.aes_gcm_decrypt(bf_decrypted, password)
            return self.engine.lzma_decompress(aes_decrypted)
        elif method_id == 33:
            decoded = self.engine.base64_decode(data)
            unxored = self.engine.xor_encrypt(decoded, 0xAA)
            decompressed = self.engine.lzma_decompress(unxored)
            chacha_decrypted = self.engine.chacha20_decrypt(decompressed, password)
            return chacha_decrypted
        elif method_id == 34:
            hex_decoded = self.engine.hex_decode(data)
            decompressed = self.engine.zlib_decompress(hex_decoded)
            des3_decrypted = self.engine.des3_decrypt(decompressed, password + "_des")
            aes_decrypted = self.engine.aes_decrypt(des3_decrypted, password + "_aes")
            return self.engine.fernet_decrypt(aes_decrypted, password)
        elif method_id == 35:
            layer5 = self.engine.fernet_decrypt(data, password + "_4")
            layer4 = self.engine.chacha20_decrypt(layer5, password + "_3")
            layer3 = self.engine.blowfish_decrypt(layer4, password + "_2")
            layer2 = self.engine.aes_decrypt(layer3, password)
            return self.engine.xor_encrypt(layer2, 0x11)
        elif method_id == 36:
            aes3 = self.engine.aes_decrypt(data, password + "_3")
            aes2 = self.engine.aes_decrypt(aes3, password + "_2")
            return self.engine.aes_decrypt(aes2, password + "_1")
        elif method_id == 37:
            import random
            seed_val = int(hashlib.md5(password.encode()).hexdigest(), 16) % (2**32)
            random.seed(seed_val)
            ops = ["xor", "b64", "aes", "zlib"]
            random.shuffle(ops)
            result = data
            for op in reversed(ops):
                if op == "xor":
                    result = self.engine.xor_encrypt(result, 0x42)
                elif op == "b64":
                    result = self.engine.base64_decode(result)
                elif op == "aes":
                    result = self.engine.aes_decrypt(result, password)
                elif op == "zlib":
                    result = self.engine.zlib_decompress(result)
            return result
        elif method_id == 38:
            decoded = self.engine.base64_decode(data)
            fernet = self.engine.fernet_decrypt(decoded, password + "_fn")
            chacha = self.engine.chacha20_decrypt(fernet, password + "_ch")
            bf = self.engine.blowfish_decrypt(chacha, password + "_bf")
            aes = self.engine.aes_decrypt(bf, password)
            lzma_d = self.engine.lzma_decompress(aes)
            return self.engine.zlib_decompress(lzma_d)
        elif method_id == 39:
            decompressed = self.engine.zlib_decompress(data)
            decoded = self.engine.base64_decode(decompressed)
            bf = self.engine.blowfish_decrypt(decoded, password + "_bf")
            aes = self.engine.aes_gcm_decrypt(bf, password)
            unsubst = self.engine.substitution_cipher(aes, forward=False)
            unxored = self.engine.xor_encrypt(unsubst, 0xFF)
            return self.engine.lzma_decompress(unxored)
        elif method_id == 40:
            layer10 = self.engine.xor_encrypt(data, 0xAD)
            layer9 = self.engine.base64_decode(layer10)
            layer8 = self.engine.zlib_decompress(layer9)
            layer7 = self.engine.fernet_decrypt(layer8, password + "_l7")
            layer6 = self.engine.chacha20_decrypt(layer7, password + "_l6")
            layer5 = self.engine.blowfish_decrypt(layer6, password + "_l5")
            layer4 = self.engine.aes_gcm_decrypt(layer5, password)
            layer3 = self.engine.substitution_cipher(layer4, forward=False)
            layer2 = self.engine.xor_encrypt(layer3, 0xDE)
            return self.engine.lzma_decompress(layer2)
        
        return data

def show_main_menu():
    smooth_transition()
    show_status_bar()
    console.print()
    display_rainbow_banner()
    
    table = Table(box=box.ROUNDED, show_header=False, padding=(0, 2))
    table.add_column("Option", style="bold cyan", width=8)
    table.add_column("Description", style="white")
    
    table.add_row("[1]", "Encrypt Python Code")
    table.add_row("[2]", "Decrypt Python Code")
    table.add_row("[3]", "View Encryption Methods")
    table.add_row("[4]", "About TitanCrypt")
    table.add_row("[5]", "View History")
    table.add_row("[0]", "Exit")
    
    width, _ = get_terminal_size()
    if width >= 100 and operation_history:
        columns = Columns([Align.center(table), show_history_panel()], expand=True)
        console.print(columns)
    else:
        console.print(Align.center(table))
        console.print()

def _generate_loader(encoded_data: str, method_id: int, needs_password: bool, is_marshal: bool) -> str:
    loader = '''# -*- coding: utf-8 -*-
# TitanCrypt Encrypted Python Script
import base64,zlib,lzma,struct,hashlib,marshal,codecs
try:
    from Crypto.Cipher import AES,Blowfish,DES3,ChaCha20
    from Crypto.Util.Padding import unpad,pad
except:
    from Cryptodome.Cipher import AES,Blowfish,DES3,ChaCha20
    from Cryptodome.Util.Padding import unpad,pad
from cryptography.fernet import Fernet
'''
    
    if needs_password:
        loader += '''from getpass import getpass
_pw=getpass("Password: ")
'''
    else:
        loader += '''_pw=None
'''
    
    loader += f'''
_DATA="{encoded_data}"
_METHOD={method_id}
_MARSHAL={str(is_marshal)}

class _D:
    @staticmethod
    def gk(pw,salt=None):
        s=salt or b"titan_salt__"
        return hashlib.pbkdf2_hmac("sha256",pw.encode(),s,100000,32),s
    @staticmethod
    def aes(d,pw):
        s,iv,ct=d[:16],d[16:32],d[32:];k,_=_D.gk(pw,s)
        return unpad(AES.new(k,AES.MODE_CBC,iv).decrypt(ct),16)
    @staticmethod
    def gcm(d,pw):
        s,n,t,ct=d[:16],d[16:32],d[32:48],d[48:];k,_=_D.gk(pw,s)
        return AES.new(k,AES.MODE_GCM,n).decrypt_and_verify(ct,t)
    @staticmethod
    def bf(d,pw):
        s,iv,ct=d[:16],d[16:24],d[24:];k,_=_D.gk(pw,s)
        return unpad(Blowfish.new(k[:56],Blowfish.MODE_CBC,iv).decrypt(ct),8)
    @staticmethod
    def d3(d,pw):
        s,iv,ct=d[:16],d[16:24],d[24:];k,_=_D.gk(pw,s)
        return unpad(DES3.new(k[:24],DES3.MODE_CBC,iv).decrypt(ct),8)
    @staticmethod
    def cc(d,pw):
        s,n,ct=d[:16],d[16:28],d[28:];k,_=_D.gk(pw,s)
        return ChaCha20.new(key=k,nonce=n).decrypt(ct)
    @staticmethod
    def fn(d,pw):
        k=base64.urlsafe_b64encode(hashlib.sha256(pw.encode()).digest())
        return Fernet(k).decrypt(d)
    @staticmethod
    def xr(d,k=0x5A):return bytes(b^k for b in d)
    @staticmethod
    def sub(d,rev=True):
        import random;random.seed(42);t=list(range(256));random.shuffle(t)
        if rev:m={{v:i for i,v in enumerate(t)}}
        else:m={{i:v for i,v in enumerate(t)}}
        return bytes(m[b] for b in d)
    @staticmethod
    def rot(d,n=13,rev=False):
        if rev:n=-n
        r=[]
        for b in d:
            if 65<=b<=90:r.append(((b-65+n)%26)+65)
            elif 97<=b<=122:r.append(((b-97+n)%26)+97)
            else:r.append(b)
        return bytes(r)

def _decrypt(d,m,pw):
    if d[:13]==b"TITAN_ENC_V1_":
        pw_len=struct.unpack("<H",d[15:17])[0]
        c=d[17+pw_len:]
    else:c=d
    if m==1:return base64.b64decode(c)
    if m==2:return _D.rot(c,-13)
    if m==3:return _D.xr(c,0x5A)
    if m==4:return _D.rot(c,-13)
    if m==5:return c.decode()[::-1].encode()
    if m==6:return bytes.fromhex(c.decode())
    if m==7:return bytes((b-7+256)%256 for b in c)
    if m==8:return base64.b64decode(_D.xr(c,0x5A))
    if m==9:return base64.b64decode(base64.b64decode(c))
    if m==10:return bytes.fromhex(base64.b64decode(c).decode())
    if m==11:return _D.aes(c,pw)
    if m==12:return _D.gcm(c,pw)
    if m==13:return _D.bf(c,pw)
    if m==14:return _D.d3(c,pw)
    if m==15:return _D.cc(c,pw)
    if m==16:return _D.fn(c,pw)
    if m==17:return _D.xr(_D.aes(c,pw),0x5A)
    if m==18:return _D.sub(c)
    if m==19:return zlib.decompress(_D.aes(c,pw))
    if m==20:return _D.fn(base64.b64decode(c),pw)
    if m==21:return _D.aes(_D.bf(c,pw+"_bf"),pw)
    if m==22:return zlib.decompress(_D.aes(base64.b64decode(c),pw))
    if m==23:return lzma.decompress(_D.cc(c,pw))
    if m==24:return _D.xr(_D.aes(_D.fn(c,pw+"_fernet"),pw),0x5A)
    if m==25:return _D.sub(_D.aes(c,pw))
    if m==26:return lzma.decompress(_D.fn(c,pw))
    if m==27:return _D.gcm(_D.bf(c,pw+"_bf"),pw)
    if m==28:return _D.aes(bytes.fromhex(c.decode()),pw)[::-1]
    if m==29:return _D.xr(_D.xr(_D.aes(c,pw),0xA5),0x5A)
    if m==30:return _D.aes(c,pw)
    if m==31:
        r=zlib.decompress(c);r=_D.sub(r);r=_D.aes(r,pw);r=_D.xr(r,0x5A);return base64.b64decode(r)
    if m==32:return lzma.decompress(_D.gcm(_D.bf(base64.b64decode(c),pw+"_bf"),pw))
    if m==33:
        r=base64.b64decode(c);r=_D.xr(r,0xAA);r=lzma.decompress(r);r=_D.cc(r,pw);return r
    if m==34:
        r=bytes.fromhex(c.decode());r=zlib.decompress(r);r=_D.d3(r,pw+"_des");r=_D.aes(r,pw+"_aes");return _D.fn(r,pw)
    if m==35:return _D.xr(_D.aes(_D.bf(_D.cc(_D.fn(c,pw+"_4"),pw+"_3"),pw+"_2"),pw),0x11)
    if m==36:return _D.aes(_D.aes(_D.aes(c,pw+"_3"),pw+"_2"),pw+"_1")
    if m==37:
        import random;seed_val=int(hashlib.md5(pw.encode()).hexdigest(),16)%(2**32);random.seed(seed_val);ops=["xor","b64","aes","zlib"];random.shuffle(ops);r=c
        for o in reversed(ops):
            if o=="xor":r=_D.xr(r,0x42)
            elif o=="b64":r=base64.b64decode(r)
            elif o=="aes":r=_D.aes(r,pw)
            elif o=="zlib":r=zlib.decompress(r)
        return r
    if m==38:
        r=base64.b64decode(c);r=_D.fn(r,pw+"_fn");r=_D.cc(r,pw+"_ch");r=_D.bf(r,pw+"_bf");r=_D.aes(r,pw);r=lzma.decompress(r);return zlib.decompress(r)
    if m==39:
        r=zlib.decompress(c);r=base64.b64decode(r);r=_D.bf(r,pw+"_bf");r=_D.gcm(r,pw);r=_D.sub(r);r=_D.xr(r,0xFF);return lzma.decompress(r)
    if m==40:
        r=_D.xr(c,0xAD);r=base64.b64decode(r);r=zlib.decompress(r);r=_D.fn(r,pw+"_l7");r=_D.cc(r,pw+"_l6");r=_D.bf(r,pw+"_l5");r=_D.gcm(r,pw);r=_D.sub(r);r=_D.xr(r,0xDE);return lzma.decompress(r)
    return c

_raw=_decrypt(base64.b64decode(_DATA),_METHOD,_pw)
if _MARSHAL:exec(marshal.loads(_raw))
else:exec(_raw.decode()if isinstance(_raw,bytes)else _raw)
'''
    
    return loader

def show_encryption_levels():
    clear_screen()
    display_rainbow_banner()
    
    for level_key, level_data in ENCRYPTION_LEVELS.items():
        console.print(Panel(
            f"[bold]{level_data['description']}[/bold]",
            title=f"[bold magenta]{level_data['name']}[/bold magenta]",
            border_style="dim"
        ))
        
        table = Table(box=box.SIMPLE, show_header=True, padding=(0, 1))
        table.add_column("ID", style="cyan", width=4)
        table.add_column("Name", style="green", width=20)
        table.add_column("Description", style="dim")
        
        for method in level_data["methods"]:
            table.add_row(str(method["id"]), method["name"], method["desc"])
        
        console.print(table)
        console.print()

def encrypt_menu():
    smooth_transition("Loading encryption menu...")
    display_rainbow_banner()
    
    console.print(Panel("[bold]Encryption Menu[/bold]", border_style="green"))
    
    file_path = Prompt.ask("[cyan]Enter Python file path[/cyan]")
    
    if not os.path.exists(file_path):
        console.print(Panel("[red]File not found![/red]", border_style="red"))
        add_to_history("Encrypt", f"File not found: {file_path}", "error")
        Prompt.ask("Press Enter to continue")
        return
    
    show_encryption_levels()
    
    method_id = IntPrompt.ask("[cyan]Select encryption method (1-40)[/cyan]", default=1)
    
    password = None
    if method_id >= 11:
        password = Prompt.ask("[cyan]Enter encryption password[/cyan]", password=True)
    
    if not confirm_action(f"Encrypt '{os.path.basename(file_path)}' using method {method_id}?", "Confirm Encryption"):
        console.print("[yellow]Encryption cancelled.[/yellow]")
        Prompt.ask("Press Enter to continue")
        return
    
    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            console=console
        ) as progress:
            task = progress.add_task("[cyan]Encrypting...", total=100)
            
            progress.update(task, advance=10, description="[cyan]Reading file...")
            with open(file_path, 'r') as f:
                code = f.read()
            time.sleep(0.1)
            
            progress.update(task, advance=30, description="[cyan]Applying encryption...")
            encryptor = TitanEncryptor()
            encrypted_data, metadata = encryptor.encrypt(code, method_id, password)
            time.sleep(0.1)
            
            progress.update(task, advance=30, description="[cyan]Encoding data...")
            encoded_data = base64.b64encode(encrypted_data).decode('utf-8')
            loader_code = _generate_loader(encoded_data, method_id, password is not None, metadata.get('is_marshal', False))
            time.sleep(0.1)
            
            progress.update(task, advance=20, description="[cyan]Writing output...")
            base_name = os.path.basename(file_path)
            dir_name = os.path.dirname(file_path)
            output_name = f"encrypted_{base_name}"
            output_file = os.path.join(dir_name, output_name) if dir_name else output_name
            
            with open(output_file, 'w') as f:
                f.write(loader_code)
            
            progress.update(task, advance=10, description="[green]Complete!")
            time.sleep(0.2)
        
        result_panel = Panel(
            f"[green]Encrypted to:[/green] [cyan]{output_file}[/cyan]\n"
            f"[dim]Method:[/dim] [yellow]{method_id}[/yellow]\n"
            f"[dim]Original:[/dim] {len(code)} bytes\n"
            f"[dim]Encrypted:[/dim] {len(loader_code)} bytes\n"
            f"[dim]File is runnable Python - executes original code[/dim]",
            title="[bold green]Encryption Complete[/bold green]",
            border_style="green"
        )
        console.print(result_panel)
        add_to_history("Encrypt", f"{base_name} (Method {method_id})", "success")
        
    except Exception as e:
        console.print(Panel(f"[red]Error: {str(e)}[/red]", title="Error", border_style="red"))
        add_to_history("Encrypt", str(e)[:30], "error")
    
    Prompt.ask("\nPress Enter to continue")

def decrypt_menu():
    smooth_transition("Loading decryption menu...")
    display_rainbow_banner()
    
    console.print(Panel("[bold]Decryption Menu[/bold]", border_style="blue"))
    
    file_path = Prompt.ask("[cyan]Enter encrypted file path[/cyan]")
    
    if not os.path.exists(file_path):
        console.print(Panel("[red]File not found![/red]", border_style="red"))
        add_to_history("Decrypt", f"File not found: {file_path}", "error")
        Prompt.ask("Press Enter to continue")
        return
    
    try:
        with console.status("[cyan]Analyzing file...[/cyan]", spinner="dots") as status:
            with open(file_path, 'rb') as f:
                data = f.read()
            
            status.update("[cyan]Detecting encryption layers...[/cyan]")
            decryptor = TitanDecryptor()
            method_id, detection_msg, analysis = decryptor.detect_encryption(data)
        
        console.print(Panel(f"[yellow]{detection_msg}[/yellow]", title="Detection Result", border_style="yellow"))
        
        if analysis and analysis.get('obfuscation', {}).get('is_obfuscated'):
            ob = analysis['obfuscation']
            console.print(f"[magenta]Obfuscation Score:[/magenta] {ob['obfuscation_score']}%")
            patterns = [p['type'].replace('_', ' ').title() for p in ob['patterns']]
            console.print(f"[dim]Patterns:[/dim] {', '.join(patterns)}")
        
        if analysis and analysis.get('total_layers', 0) > 0:
            console.print(f"\n[cyan]Layers Found:[/cyan] {analysis['total_layers']}")
            layer_table = Table(box=box.SIMPLE, show_header=True, padding=(0, 1))
            layer_table.add_column("#", style="dim", width=3)
            layer_table.add_column("Type", style="green", width=18)
            layer_table.add_column("Confidence", style="yellow", width=12)
            layer_table.add_column("Size", style="dim", width=18)
            
            for layer in analysis.get('layers', []):
                conf = layer.get('confidence', 'N/A')
                conf_str = f"{conf}%" if isinstance(conf, (int, float)) else str(conf)
                layer_table.add_row(
                    str(layer['layer']),
                    layer['type'].upper(),
                    conf_str,
                    f"{layer['size_before']} → {layer['size_after']}"
                )
            console.print(layer_table)
        
        password = None
        if method_id >= 11 or method_id == -2:
            password = Prompt.ask("[cyan]Enter decryption password[/cyan]", password=True)
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            console=console
        ) as progress:
            task = progress.add_task("[cyan]Decrypting...", total=100)
            
            progress.update(task, advance=30, description="[cyan]Decrypting layers...")
            decrypted_data, metadata = decryptor.decrypt(data, password)
            progress.update(task, advance=70, description="[green]Complete!")
            time.sleep(0.2)
        
        base_name = os.path.basename(file_path)
        dir_name = os.path.dirname(file_path)
        if base_name.endswith('.py'):
            output_name = f"decrypted_{base_name}"
        else:
            output_name = f"decrypted_{base_name.rsplit('.', 1)[0]}.py"
        output_file = os.path.join(dir_name, output_name) if dir_name else output_name
        
        is_marshal = False
        decompiled_source = None
        
        if len(decrypted_data) > 2 and decrypted_data[0:2] in [b'\xe3\x00', b'\xe3\x01', b'\xe3\x02', b'\xe3\x03']:
            is_marshal = True
            console.print("[yellow]Detected marshal bytecode, attempting decompilation...[/yellow]")
            
            code_obj = None
            try:
                import marshal as marshal_mod
                code_obj = marshal_mod.loads(decrypted_data)
            except Exception as marshal_err:
                console.print(f"[yellow]Marshal load failed (cross-version issue): {str(marshal_err)}[/yellow]")
                console.print("[dim]Attempting cross-version recovery...[/dim]")
            
            if code_obj:
                try:
                    import uncompyle6
                    import io
                    output_buffer = io.StringIO()
                    uncompyle6.code_deparse(code_obj, out=output_buffer)
                    decompiled_source = output_buffer.getvalue()
                    console.print("[green]Decompilation successful![/green]")
                except Exception as decomp_err:
                    console.print(f"[yellow]Decompilation failed: {str(decomp_err)}[/yellow]")
                    try:
                        import dis
                        import io
                        output_buffer = io.StringIO()
                        dis.dis(code_obj, file=output_buffer)
                        disasm = output_buffer.getvalue()
                        decompiled_source = f"# Disassembled bytecode (decompilation failed)\n# Original code object: {code_obj.co_filename}\n\n'''\n{disasm}\n'''"
                        console.print("[yellow]Falling back to disassembly view[/yellow]")
                    except:
                        pass
            
            if not decompiled_source:
                strings = re.findall(rb'[\x20-\x7e]{4,}', decrypted_data)
                identifiers = []
                class_names = []
                func_names = []
                
                for s in strings:
                    try:
                        decoded = s.decode('utf-8')
                        if decoded.startswith('class ') or decoded.endswith('c') and decoded[:-1].isidentifier():
                            class_names.append(decoded)
                        elif decoded.startswith('def ') or '.' in decoded and '<' not in decoded:
                            func_names.append(decoded)
                        elif decoded.isidentifier() and len(decoded) > 2:
                            identifiers.append(decoded)
                    except:
                        pass
                
                unique_strings = list(set([s.decode('utf-8', errors='ignore') for s in strings]))
                
                header = "# Extracted code structure from marshal bytecode\n"
                header += "# (Full decompilation failed - marshal format from different Python version)\n\n"
                header += "# === Classes found ===\n"
                for cls in set(class_names):
                    if cls.endswith('c'):
                        header += f"# class {cls[:-1]}:\n"
                
                header += "\n# === Functions/Methods found ===\n"
                for fn in set(func_names):
                    if '.' in fn:
                        header += f"#   {fn}\n"
                
                header += "\n# === String literals found ===\n"
                for s in unique_strings[:50]:
                    if len(s) > 3 and not s.startswith('__') and '<' not in s:
                        header += f"#   \"{s}\"\n"
                
                header += "\n# === Identifiers ===\n"
                header += f"# {', '.join(list(set(identifiers))[:30])}\n"
                
                header += "\n# To fully decompile, run this file with the same Python version it was encrypted with.\n"
                
                decompiled_source = header
                console.print("[yellow]Extracted code structure (cross-version marshal)[/yellow]")
        
        if decompiled_source:
            with open(output_file, 'w') as f:
                f.write(decompiled_source)
        else:
            try:
                output_content = decrypted_data.decode('utf-8')
                with open(output_file, 'w') as f:
                    f.write(output_content)
            except:
                output_file = output_file.rsplit('.', 1)[0] + '.bin'
                with open(output_file, 'wb') as f:
                    f.write(decrypted_data)
        
        result_text = f"[green]Decrypted to:[/green] [cyan]{output_file}[/cyan]\n"
        if metadata.get('method'):
            result_text += f"[dim]Method:[/dim] [yellow]{metadata.get('method_name', metadata.get('method'))}[/yellow]\n"
        if metadata.get('layers'):
            result_text += f"[dim]Layers Decoded:[/dim] [cyan]{metadata.get('layers')}[/cyan]\n"
        if metadata.get('is_plaintext'):
            result_text += f"[dim]Status:[/dim] [green]Raw Python code recovered[/green]\n"
        result_text += f"[dim]Output size:[/dim] {len(decrypted_data)} bytes"
        
        console.print(Panel(result_text, title="[bold green]Decryption Complete[/bold green]", border_style="green"))
        add_to_history("Decrypt", f"{base_name}", "success")
        
    except Exception as e:
        console.print(Panel(f"[red]Error: {str(e)}[/red]", title="Error", border_style="red"))
        add_to_history("Decrypt", str(e)[:30], "error")
    
    Prompt.ask("\nPress Enter to continue")

def show_history():
    smooth_transition("Loading history...")
    display_rainbow_banner()
    
    if not operation_history:
        console.print(Panel("[dim]No operations recorded yet.[/dim]", title="History", border_style="dim"))
    else:
        table = Table(box=box.ROUNDED, title="Operation History", show_header=True)
        table.add_column("Time", style="dim", width=10)
        table.add_column("Operation", style="cyan", width=15)
        table.add_column("Details", style="white", width=40)
        table.add_column("Status", width=10)
        
        for entry in reversed(operation_history):
            status_style = "green" if entry["status"] == "success" else "red"
            table.add_row(
                entry["time"],
                entry["operation"],
                entry["details"],
                f"[{status_style}]{entry['status'].upper()}[/{status_style}]"
            )
        
        console.print(table)
    
    Prompt.ask("\nPress Enter to continue")

def show_about():
    smooth_transition("Loading about...")
    display_rainbow_banner()
    
    width, _ = get_terminal_size()
    
    about_text = """
[bold cyan]TitanCrypt[/bold cyan] - Python Code Encryption & Decryption Tool

[dim]Version:[/dim] 1.0
[dim]Author:[bold magenta] Walter[/bold magenta]

[bold]Features:[/bold]
• 40 encryption methods from basic to ultra-secure
• [cyan]Universal Auto-Detection[/cyan] - Decodes ANY encrypted Python
• Perfect layer-by-layer analysis with confidence scoring
• Detects Base64, Hex, XOR, ROT13, Zlib, LZMA, AES, Marshal
• Password-protected encryption
• Multi-layer obfuscation support
• Progress indicators & smooth transitions
• Operation history tracking

[bold]Encryption Levels:[/bold]
• [green]Low (1-10):[/green] Basic obfuscation, no password needed
• [yellow]Medium (11-20):[/yellow] Standard encryption, password required
• [red]High (21-30):[/red] Multi-layer encryption
• [magenta]Ultra (31-40):[/magenta] Maximum security, multiple layers

[bold blue]Join Discord:[/bold blue] [link=https://discord.gg/rgWcEw5G8a]https://discord.gg/rgWcEw5G8a[/link]

[dim]Use responsibly. Protect your code.[/dim]
"""
    
    console.print(Panel(about_text, title="[bold]About TitanCrypt[/bold]", border_style="cyan"))
    Prompt.ask("\nPress Enter to continue")

def main():
    while True:
        show_main_menu()
        
        choice = Prompt.ask("[bold cyan]Select option[/bold cyan]", choices=["0", "1", "2", "3", "4", "5"], default="0")
        
        if choice == "0":
            smooth_transition()
            console.print(Panel("[dim]Thank you for using TitanCrypt. Goodbye![/dim]", border_style="cyan"))
            break
        elif choice == "1":
            encrypt_menu()
        elif choice == "2":
            decrypt_menu()
        elif choice == "3":
            show_encryption_levels()
            Prompt.ask("\nPress Enter to continue")
        elif choice == "4":
            show_about()
        elif choice == "5":
            show_history()

if __name__ == "__main__":
    main()
