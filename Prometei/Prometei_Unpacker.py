# Description: Prometei helper script, decrypt text/data sections
# Author: @YungBinary

import pefile
import argparse

# Replace me with the first byte you find in C:\Windows\mshlpda32.dll
CONSTANT = 0x31

def get_section_offset_size(pe: pefile.PE, section_name: str) -> tuple[int, int]:
    """
    Get a PE file section offset and size.
    returns:
        a tuple with the section offset and size
    """
    for section in pe.sections:
        name = section.Name.decode().rstrip('\x00')
        if name == section_name:
            return section.VirtualAddress, section.SizeOfRawData
    return None, None


def xor_decrypt(data: bytes, constant: int) -> bytes:
    """
    XOR decrypt with rolling key
    args:
        data: a bytes object representing the encrypted data
        constant: a magic number used to transform the XOR key,
                  e.g. "1" or \x31
    returns:
        a bytes object representing the decrypted data
    """

    result = bytearray()
    shift = 0
    counter = 0

    for byte in data:
        result.append(((shift + counter) & 0xFF) ^ byte)
        shift = (shift + constant) & 0xFF
        counter = (counter - 1) & 0xFF
    
    return bytes(result)


def main():
    logo = """
███████╗░██████╗███████╗███╗░░██╗████████╗██╗██████╗░███████╗
██╔════╝██╔════╝██╔════╝████╗░██║╚══██╔══╝██║██╔══██╗██╔════╝
█████╗░░╚█████╗░█████╗░░██╔██╗██║░░░██║░░░██║██████╔╝█████╗░░
██╔══╝░░░╚═══██╗██╔══╝░░██║╚████║░░░██║░░░██║██╔══██╗██╔══╝░░
███████╗██████╔╝███████╗██║░╚███║░░░██║░░░██║██║░░██║███████╗
╚══════╝╚═════╝░╚══════╝╚═╝░░╚══╝░░░╚═╝░░░╚═╝╚═╝░░╚═╝╚══════╝
"""
    print(logo)
    print("Unpack Prometei Botnet!")
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--file', required=True)
    parser.add_argument('-o', '--outfile', required=True)
    args = parser.parse_args()

    # Load the PE file
    pe = pefile.PE(args.file)

    # Get the .data section offset/size
    data_start, data_size = get_section_offset_size(pe, ".data")
    print(f"Decrypting .data section at offset: {hex(data_start)}, size: {hex(data_size)}.")

    # Decrypt the .data section and replace encrypted bytes with decrypted bytes
    encrypted_data = pe.get_data(data_start, data_size)
    decrypted_data = xor_decrypt(encrypted_data, CONSTANT)
    pe.set_bytes_at_offset(data_start, decrypted_data)

    # Get the .text section offset/size
    text_start, text_size = get_section_offset_size(pe, ".text")
    print(f"Decrypting .text section at offset: {hex(text_start)}, size: {hex(text_size)}.")

    # Decrypt the .text section and replace encrypted bytes with decrypted bytes
    encrypted_data = pe.get_data(text_start, text_size)
    decrypted_data = xor_decrypt(encrypted_data, CONSTANT)
    pe.set_bytes_at_offset(text_start, decrypted_data)

    # Write the patched file to args.outfile
    pe.write(args.outfile)
    print(f"Decryption finished, output file written to: {args.outfile}.")

if __name__ == "__main__":
    main()

