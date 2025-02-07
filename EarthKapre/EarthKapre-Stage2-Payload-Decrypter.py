import hashlib
import struct
import yara
import argparse
import pefile
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from itertools import cycle


RULE_SOURCE_XOR_KEY = """rule EarthKapreXorKey
{
    meta:
        author = "YungBinary"
    strings:
        $xorkey = {
			44 8D 43 ??
			48 8D 15 ?? ?? ?? ??
			48 8D 4D ??
			E8 ?? ?? ?? ??
		}
    condition:
        $xorkey
}"""


def file_offset_to_memory_offset(pe, file_offset):
    image_base = pe.OPTIONAL_HEADER.ImageBase
    for section in pe.sections:
        section_start = section.PointerToRawData
        section_end = section_start + section.SizeOfRawData
        if section_start <= file_offset < section_end:
            memory_offset = section.VirtualAddress + (file_offset - section_start)
            return memory_offset


def memory_address_to_file_offset(pe, memory_address):
    image_base = pe.OPTIONAL_HEADER.ImageBase
    for section in pe.sections:
        section_va = section.VirtualAddress
        section_start = section.PointerToRawData
        section_end = section_start + section.SizeOfRawData
        if section_va <= memory_address < section_va + section.SizeOfRawData:
            file_offset = section_start + (memory_address - section_va)
            return file_offset


def yara_scan(raw_data, rule_source):
    yara_rules = yara.compile(source=rule_source)
    matches = yara_rules.match(data=raw_data)

    for match in matches:
        for block in match.strings:
            for instance in block.instances:
                yield block.identifier, instance.offset


def find_xor_key(pe, data):
    for match in yara_scan(data, RULE_SOURCE_XOR_KEY):
        rule_str_name, offset = match
        xor_str_displacement = data[offset + 7 : offset + 11]
        xor_mem_offset = file_offset_to_memory_offset(pe, offset)
        xor_str_offset = xor_mem_offset + struct.unpack("i", xor_str_displacement)[0] + 11
        xor_str_file_offset = memory_address_to_file_offset(pe, xor_str_offset)
        xor_key_size = data[offset + 3]
        xor_key = data[xor_str_file_offset : xor_str_file_offset + xor_key_size]
        return xor_key


def xor_data(data, key):
    return bytes(c ^ k for c, k in zip(data, cycle(key)))


def decrypt_payload(pe, first_stage, encrypted_payload):
    xor_key = find_xor_key(pe, first_stage)
    print(f"Found XOR key: {xor_key}")
    decrypted_payload_with_junk = xor_data(encrypted_payload, xor_key)
    ms_dos_offset = decrypted_payload_with_junk.index(b"This program cannot be run in DOS mode")
    decrypted_payload = decrypted_payload_with_junk[ms_dos_offset - 0x4E:]
    if not decrypted_payload[:2] == b"MZ":
        raise Exception("Failed to find MZ header, decryption not successful...")
    return decrypted_payload


def read_file(path):
    with open(path, "rb") as f:
        return f.read()


def write_file(data, path):
    with open(path, "wb") as f:
        return f.write(data)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--first-stage', required=True, help='Path to the first stage of EarthKapre (unpacked).')
    parser.add_argument('-e', '--encrypted-payload', required=True, help='Path to the encrypted EarthKapre payload retrieved from C2.')
    parser.add_argument('-o', '--out-file', required=True, help='Output file path to write decrypted payload.')
    args = parser.parse_args()

    first_stage = read_file(args.first_stage)

    pe = pefile.PE(data=first_stage, fast_load=False)
    encrypted_payload = read_file(args.encrypted_payload)
    decrypted_payload = decrypt_payload(pe, first_stage, encrypted_payload)
    write_file(decrypted_payload, args.out_file)
    print(f"Successfully decrypted payload, output file path: {args.out_file}")

if __name__ == "__main__":
    main()

