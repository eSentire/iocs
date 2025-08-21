"""

Author: @YungBinary
Use case: Use this script to verify ransomware using Curve-25519 + AES-128-CTR,
             where the Curve-25519 shared secret is SHA512'd and the first 16 bytes
             used as the AES key, and latter 16 bytes used for the counter block

             Note: The ransomware may use a specific chunking size, in that case, this script will need to be modified.

SHA256 of Sinobi ransomware payload: 1b2a1e41a7f65b8d9008aa631f113cef36577e912c13f223ba8834bbefa4bd14

"""


from cryptography.hazmat.primitives.asymmetric import x25519
from Crypto.Cipher import AES
from Crypto.Util import Counter
from cryptography.hazmat.primitives import serialization
import hashlib
import base64

# Set to a path below to a plaintext file encrypted by the ransomware
# So you can verify this script's ciphertext with the ransomware's ciphertext
PLAINTEXT_FILE_PATH = "REPLACE"

# Set to the attacker's Curve-25519 public key, stored as base64 string in Sinobi ransomware
ATTACKER_CURVE_25519_PUBLIC_KEY_BYTES = base64.b64decode("BFthuj+0R46aVsiXII9U83iOpHbO0LE7ZQMnFRExDZo=")

# Replace with private key generated in the ransomware
# For example, CryptGenRandom is used in Sinobi to generate the 32 byte key
VICTIM_CURVE_25519_PRIVATE_KEY_BYTES = bytes.fromhex("DE 84 27 96 C0 A7 1B 5F EB FC 68 8C FF 80 80 AA 9B 33 65 FC 50 08 43 46 82 6B 14 4C 7F 79 09 27")


def print_hex_dump(data: bytes):
    def to_printable_ascii(byte):
        return chr(byte) if 32 <= byte <= 126 else "."

    offset = 0
    while offset < len(data):
        chunk = data[offset : offset + 16]
        hex_values = " ".join(f"{byte:02x}" for byte in chunk)
        ascii_values = "".join(to_printable_ascii(byte) for byte in chunk)
        print(f"{offset:08x}  {hex_values:<48}  |{ascii_values}|")
        offset += 16


def main():
    # Load victim's private key
    victim_private_key = x25519.X25519PrivateKey.from_private_bytes(VICTIM_CURVE_25519_PRIVATE_KEY_BYTES)
    ephemeral_pub = victim_private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    # Sinobi ransomware stores this in each encrypted file's footer
    print("Ephemeral Public:")
    print_hex_dump(ephemeral_pub)

    # Load attacker's public key
    attacker_public_key = x25519.X25519PublicKey.from_public_bytes(ATTACKER_CURVE_25519_PUBLIC_KEY_BYTES)

    # Perform ECDH to get shared secret
    shared_secret = victim_private_key.exchange(attacker_public_key)
    print("Shared Secret:")
    print_hex_dump(shared_secret)

    # Generate SHA512 of the shared secret bytes
    shared_secret_sha512 = hashlib.sha512()
    shared_secret_sha512.update(shared_secret)
    shared_secret_sha512 = shared_secret_sha512.digest()

    print("Shared Secret SHA512:")
    print_hex_dump(shared_secret_sha512)

    ephemeral_pub_sha512 = hashlib.sha512()
    ephemeral_pub_sha512.update(ephemeral_pub)
    ephemeral_pub_sha512 = ephemeral_pub_sha512.digest()

    # Sinobi ransomware stores this in each encrypted file's footer
    print("Ephemeral Public SHA512:")
    print_hex_dump(ephemeral_pub_sha512)

    # Derive AES key from first 16 bytes
    # and counter block from latter 16 bytes
    aes_key = shared_secret_sha512[:16]
    counter_block_bytes = shared_secret_sha512[16:32]
    print("AES-128-CTR Key:")
    print_hex_dump(aes_key)
    print("AES-128-CTR Counter Block Bytes:")
    print_hex_dump(counter_block_bytes)

    with open(PLAINTEXT_FILE_PATH, "rb") as f:
        plaintext = f.read()

    ctr = Counter.new(
        128,
        initial_value=int.from_bytes(counter_block_bytes, 'big')
    )
    cipher = AES.new(
        aes_key,
        AES.MODE_CTR,
        counter=ctr
    )

    # Encrypt the plaintext
    ciphertext = cipher.encrypt(plaintext)
    print("Ciphertext:")
    print_hex_dump(ciphertext)

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
    print("Verify ransomware encryption using Curve-25519 + AES-128-CTR.")
    main()