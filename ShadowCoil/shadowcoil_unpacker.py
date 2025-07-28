import base64
import os
from Crypto.Hash import SHA256
import zlib
import hashlib
from Crypto.Protocol.KDF import PBKDF2, HKDF
from Crypto.Cipher import AES, ChaCha20
import re
import codecs
from Crypto.Util import Counter
import blake3
import argparse


PATTERN_MAP = {
    "chacha_decrypt": r"\(key=b['\"](.+?)['\"], nonce", #ChaCha20 key
    "aes_gcm_decrypt": r"\(['\"](.+?)['\"], salt, dkLen=32, count=(.+?)\)", # Capture password and count for PBKDF2 for AES-GCM
    "xor_blake3_decrypt": r"key=HKDF\(b['\"](.+?)['\"], 32, salt=b['\"](.+?)['\"], hashmod=", # Capture master_secret and salt for Blake3
    "aes_ctr_decrypt": r"AES.new\(b['\"](.+?)['\"],", # AES CTR key
}


def chacha_decrypt(data: bytes, key: bytes) -> bytes:
    nonce = data[:12]
    ct = data[12:]
    cipher = ChaCha20.new(key=key, nonce=nonce)
    data = cipher.decrypt(ct)
    return data


def aes_gcm_decrypt(data: bytes, password: str, count: int) -> bytes:
    salt = data[:16]
    nonce = data[16:32]
    tag = data[32:48]
    ct = data[48:]
    key = PBKDF2(password, salt, dkLen=32, count=count)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    data = cipher.decrypt_and_verify(ct, tag)
    return data


def xor_blake3_decrypt(data: bytes, master_secret: bytes, salt: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(data, blake3.blake3(b'', key=HKDF(master_secret, 32, salt=salt, hashmod=SHA256)).digest(len(data))))


def aes_ctr_decrypt(data: bytes, key: bytes) -> bytes:
    nonce = data[:16]
    ct = data[16:]
    initial_value = int.from_bytes(nonce, 'big')
    ctr = Counter.new(128, initial_value=initial_value)
    cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
    data = cipher.decrypt(ct)
    return data


def get_ciphertext(script_contents: str) -> bytes:
    pattern = r"exec\(pc_start\('(.+?)'\)\)"
    match = re.search(pattern.encode(), script_contents)
    decoded = b''
    if match:
        captured = match.group(1)
        decoded = base64.b85decode(captured)
    return decoded

def unescape_to_bytes(s: str) -> bytes:
    return s.decode('unicode_escape').encode('latin1')

def decrypt(outfile: str, data: bytes):
    
    decrypted = data
    total_stages_decrypted = 0
    while True:
        
        # Determine the order needed to decrypt the data
        matches_found = []

        # Iterate through each pattern
        for name, pattern in PATTERN_MAP.items():
            # Find all non-overlapping matches for the current pattern
            pattern = pattern.encode()
            regex_obj = re.compile(pattern)
            for match_obj in regex_obj.finditer(decrypted):
                start_index = match_obj.start()

                matches_found.append(
                    (start_index, match_obj.groups(), name)
                )


        # Sort all found matches by start index
        matches_found.sort(key=lambda x: x[0])
        # Get the current cipher text
        cipher_text = get_ciphertext(decrypted)
        if not cipher_text:
            break

        # Use keys, salts, etc identified in regex matches
        for match_data in matches_found:
            start_idx, capture_groups, pattern_name = match_data
            if pattern_name == "chacha_decrypt":
                key = unescape_to_bytes(capture_groups[0])
                cipher_text = chacha_decrypt(cipher_text, key)

            elif pattern_name == "aes_gcm_decrypt":
                password = capture_groups[0].decode()
                count = int(capture_groups[1])
                cipher_text = aes_gcm_decrypt(cipher_text, password, count)

            elif pattern_name == "xor_blake3_decrypt":
                master_secret = unescape_to_bytes(capture_groups[0])
                salt = unescape_to_bytes(capture_groups[1])
                cipher_text = xor_blake3_decrypt(cipher_text, master_secret, salt)

            elif pattern_name == "aes_ctr_decrypt":
                key = unescape_to_bytes(capture_groups[0])
                cipher_text = aes_ctr_decrypt(cipher_text, key)
        
        # Decompress after finishing this round of decryption
        decrypted = zlib.decompress(cipher_text)
        total_stages_decrypted += 1

    print(f"Finished decrypting {total_stages_decrypted} total stages to: {outfile}")
    with open(outfile, "wb") as f:
        f.write(decrypted)


if __name__ == "__main__":
    logo = """
███████╗░██████╗███████╗███╗░░██╗████████╗██╗██████╗░███████╗
██╔════╝██╔════╝██╔════╝████╗░██║╚══██╔══╝██║██╔══██╗██╔════╝
█████╗░░╚█████╗░█████╗░░██╔██╗██║░░░██║░░░██║██████╔╝█████╗░░
██╔══╝░░░╚═══██╗██╔══╝░░██║╚████║░░░██║░░░██║██╔══██╗██╔══╝░░
███████╗██████╔╝███████╗██║░╚███║░░░██║░░░██║██║░░██║███████╗
╚══════╝╚═════╝░╚══════╝╚═╝░░╚══╝░░░╚═╝░░░╚═╝╚═╝░░╚═╝╚══════╝
"""
    print(logo)
    print("Unpacks RansomHub/ShadowCoil python scripts.")
    parser = argparse.ArgumentParser(description="Unpacks RansomHub affiliated python scripts.")
    parser.add_argument('-i', '--in-path', help='Input file (or file path containing packed files) to decrypt.', required=True)
    parser.add_argument('-o', '--out-path', help='Output file (or path if input is a directory).', required=True)
    args = parser.parse_args()

    if os.path.isdir(args.in_path):
        print(f"Unpacking files in: {args.in_path}, to: {args.out_path}")
        os.makedirs(args.out_path, exist_ok=True)
        for root, directories, files in os.walk(args.in_path):
            for file in files:
                in_file = os.path.join(root, file)
                out_file = os.path.join(args.out_path, file + "_unpacked.py")
                with open(in_file, "rb") as f:
                    decrypt(out_file, f.read())
    else:
        with open(args.in_path, "rb") as f:
            decrypt(args.out_path, f.read())
