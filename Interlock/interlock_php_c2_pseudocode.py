import gzip
import secrets


def decrypt_response_payload(response_payload):
    """
    Interlock group returns an XOR encrypted response
    Last 4 bytes is the XOR key
    """
    # XOR key is last four bytes
    xor_key = response_payload[-4:]
    print(f"Decrypting response using identified XOR key (last four bytes of response data): {xor_key.hex()}")
    # Cipher text is remaining bytes
    ciphertext = response_payload[:-4]
    # First byte of the XOR key is used in algorithm
    plaintext = interlock_xor(ciphertext, xor_key)
    return plaintext


def decrypt_request_payload(compressed_data):
    """
    Interlock group uses this algorithm for decryption 
    of transmitted victim system information to their C2
    """
    # Gzip decompress
    decompressed = gzip.decompress(compressed_data)
    # XOR key is last four bytes
    xor_key = decompressed[-4:]
    print(f"Decrypting using identified XOR key (last four bytes of compressed data): {xor_key.hex()}")
    # Cipher text is remaining bytes
    ciphertext = decompressed[:-4]
    # First byte of the XOR key is used in algorithm
    plaintext = interlock_xor(ciphertext, xor_key)
    return plaintext


def generate_request_payload(plaintext):
    """
    Interlock group uses this algorithm for encrypting
    and compressing system information before its sent to their C2
    """

    # Generate a 32-bit XOR key
    xor_key = secrets.token_bytes(4)
    print(f"Encrypting using XOR key: {xor_key.hex()}")
    # Loop each byte of the plaintext and XOR to produce ciphertext
    ciphertext = interlock_xor(plaintext, xor_key)
    ciphertext = ciphertext + xor_key
    # Compress the ciphertext + xor key
    compressed_ciphertext = gzip.compress(ciphertext)
    return compressed_ciphertext


def interlock_xor(data, xor_key):
    # Interlock group uses this algorithm for encryption/decryption
    result = bytearray()
    ad = xor_key[0]

    for i, byte in enumerate(data):
        ad = (ad + (ad + i % 256)) % 256
        key_byte = xor_key[i % 4]
        result.append(byte ^ (key_byte ^ ad))

    return bytes(result)

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
    print("Decrypt Interlock's PHP Backdoor C2 communications.")
    # Example use of decrypt_request_payload method
    # Normally this would be encrypted system info used by Interlock Group's PHP based backdoor
    plaintext = b"YungBinary was here!"
    print(f"Encrypting/compressing plaintext: {plaintext}")
    compressed_ciphertext = generate_request_payload(plaintext)
    print(f"Compressed ciphertext: {compressed_ciphertext.hex()}")
    plaintext = decrypt_request_payload(compressed_ciphertext)
    print(f"Decrypted plaintext: {plaintext}")

    # If you have a sample response from C2 you can decrypt it with
    # this method
    #decrypt_response_payload(response_payload)
