import hashlib
import struct
import yara
import pefile
import idaapi
import idc
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad


RULE_SOURCE_DECRYPT = """rule EarthKapreDecrypt
{
    meta:
        author = "YungBinary"
    strings:
        $decrypt = {
            4C 8D [1-5]
            48 8D 15 ?? ?? ?? ??
            48 8D [1-5]
            E8
        }
    condition:
        $decrypt
}"""

RULE_SOURCE_KEY = """rule EarthKapreKeyStage1
{
    meta:
        author = "YungBinary"
    strings:
        $key = {
			C7 4? [5-6]
			C7 4? [5-6]
			C7 4? [5-6]
			C7 4? [5-6]
			41 B8 ?? ?? ?? ??
			48 8D 5? ??
			48 8D 4? [1-2]
			E8
		}
    condition:
        $key
}"""


RULE_SOURCE_KEY_STAGE2 = """rule EarthKapreKeyStage2
{
    meta:
        author = "YungBinary"
    strings:
        $key = {
            66 0F 6F ?? ?? ?? ?? ??
            F3 0F 7F [1-5]
            41 B8 ?? ?? ?? ??
            48 8D [1-5]
            48 8D [1-5]
            E8
        }
    condition:
        $key
}"""

def yara_scan(raw_data, rule_source):
    yara_rules = yara.compile(source=rule_source)
    matches = yara_rules.match(data=raw_data)

    for match in matches:
        for block in match.strings:
            for instance in block.instances:
                yield block.identifier, instance.offset


def get_sha256_hash(string):
  hash_object = hashlib.sha256()
  hash_object.update(string) 
  hex_dig = hash_object.hexdigest()
  return hex_dig


def decrypt_aes(key, ciphertext):
    iv = 16 * b"\x00"
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_plaintext = cipher.decrypt(ciphertext)
    plaintext = unpad(padded_plaintext, AES.block_size)
    return plaintext.decode()


def find_xor_encrypted_strings(pe, data):
    key_strings = []
    for match in yara_scan(data, RULE_SOURCE_KEY):
        try:
            rule_str_name, key_str_offset = match
            xor_key = int.from_bytes(data[key_str_offset + 3 : key_str_offset + 7], byteorder="little")
            part_1 = data[key_str_offset + 10 : key_str_offset + 14]
            part_2 = data[key_str_offset + 17 : key_str_offset + 21]
            part_3 = data[key_str_offset + 24 : key_str_offset + 28]
            encrypted_data = part_1 + part_2 + part_3
            result = decrypt_xor_aes_key(encrypted_data, xor_key)
            key_strings.append(result)
            mem_offset = file_offset_to_memory_offset(pe, key_str_offset)
            print(f"Found XOR encrypted string at memory offset: {hex(mem_offset + idaapi.get_imagebase())}, file offset: {hex(key_str_offset)}, result: {result.decode()}")
            idc.set_cmt(mem_offset + idaapi.get_imagebase(), result.decode(), 0)
        except Exception:
            continue
    return key_strings


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


def decrypt_xor(encrypted, xor_key):
    output = bytearray()
    output.append((xor_key & 0xFF) ^ encrypted[0])
    a = signed_to_int32(xor_key * 48271)
    output.append((a & 0xFF) ^ encrypted[1])
    b = signed_to_int32(a * 48271)
    output.append((b & 0xFF) ^ encrypted[2])
    c = signed_to_int32(b * 48271)
    output.append((c & 0xFF) ^ encrypted[3])
    d = signed_to_int32(c * 48271)
    output.append((d & 0xFF) ^ encrypted[4])
    e = signed_to_int32(d * 48271)
    output.append((e & 0xFF) ^ encrypted[5])
    f = signed_to_int32(e * 48271)
    output.append((f & 0xFF) ^ encrypted[6])
    g = signed_to_int32(f * 48271)
    output.append((g & 0xFF) ^ encrypted[7])
    h = signed_to_int32(g * 48271)
    output.append((h & 0xFF) ^ encrypted[8])
    i = signed_to_int32(h * 48271)
    output.append((i & 0xFF) ^ encrypted[9])
    j = signed_to_int32(i * 48271)
    output.append((j & 0xFF) ^ encrypted[10])
    k = signed_to_int32(48271 * signed_to_int32(i * 48271))
    output.append((k & 0xFF) ^ encrypted[11])
    l = signed_to_int32(48271 * signed_to_int32(j * 48271))
    output.append((l & 0xFF) ^ encrypted[12])
    if len(encrypted) > 14:
        m = signed_to_int32(48271 * signed_to_int32(k * 48271))
        output.append((m & 0xFF) ^ encrypted[13])
    return output


def decrypt_xor_aes_key(encrypted, xor_key):
    output = bytearray()
    output.append((xor_key & 0xFF) ^ encrypted[0])
    a = signed_to_int32(xor_key * 48271)
    output.append((a & 0xFF) ^ encrypted[1])
    b = signed_to_int32(a * 48271)
    output.append((b & 0xFF) ^ encrypted[2])
    c = signed_to_int32(b * 48271)
    output.append((c & 0xFF) ^ encrypted[3])
    d = signed_to_int32(c * 48271)
    output.append((d & 0xFF) ^ encrypted[4])
    e = signed_to_int32(d * 48271)
    output.append((e & 0xFF) ^ encrypted[5])
    f = signed_to_int32(e * 48271)
    output.append((f & 0xFF) ^ encrypted[6])
    g = signed_to_int32(f * 48271)
    output.append((g & 0xFF) ^ encrypted[7])
    h = signed_to_int32(g * 48271)
    output.append((h & 0xFF) ^ encrypted[8])
    i = signed_to_int32(h * 48271)
    output.append((i & 0xFF) ^ encrypted[9])
    j = signed_to_int32(i * 48271)
    output.append((j & 0xFF) ^ encrypted[10])
    return output


def find_xor_encrypted_data(pe, data):
    for match in yara_scan(data, RULE_SOURCE_KEY_STAGE2):
        try:
            rule_str_name, key_str_offset = match
            key_str_displacement = data[key_str_offset + 4 : key_str_offset + 8]
            data_chunk = data[key_str_offset : key_str_offset + 40]
            xor_key_opcodes = b"\x41\xB8"
            xor_key_offset = data_chunk.index(xor_key_opcodes)
            xor_key = struct.unpack("i", data[key_str_offset + xor_key_offset + 2 : key_str_offset + xor_key_offset + 6])[0]
            str_decrypt_mem_offset = file_offset_to_memory_offset(pe, key_str_offset)
            encrypted_key_offset = memory_address_to_file_offset(pe, str_decrypt_mem_offset + struct.unpack("i", key_str_displacement)[0] + 8)
            encrypted_key = pe.get_string_from_data(encrypted_key_offset, data)
            yield encrypted_key, xor_key, key_str_offset
        except Exception:
            continue


def signed_to_int32(value):
    value = value & 0xFFFFFFFF
    if value > 0x7FFFFFFF:
        value -= 0x7FFFFFFF
    return value


def main():
    # If decoding stage 2 set this, otherwise set to None or False
    #SECRET = b'c7ccd991-41e1-45ab-b0de-b1d229bba429'
    SECRET = None
    loaded_bin_path = idc.get_input_file_path()

    with open(loaded_bin_path, "rb") as f:
        data = f.read()

    pe = pefile.PE(data=data, fast_load=False)

    key_strings = []

    # Stage 1
    if not SECRET:
        key_strings = find_xor_encrypted_strings(pe, data)

    # Stage 2
    else:
        for key_str, xor_key, offset in find_xor_encrypted_data(pe, data):
            try:
                decrypted_string = decrypt_xor(key_str, xor_key)
                mem_offset = file_offset_to_memory_offset(pe, offset)
                print(f"Decrypting string at memory offset {hex(mem_offset + idaapi.get_imagebase())}, file offset {hex(offset)}, result: {decrypted_string.decode()}")
                idc.set_cmt(mem_offset + idaapi.get_imagebase(), decrypted_string.decode(), 0)
                key_strings.append(decrypted_string)
            except Exception:
                continue

    # Loop through each string trying each as an AES key
    for string in key_strings:

        try:

            key_string = string

            #if SECRET:
            #    key_string += SECRET

            # Create 16 byte AES key
            sha256 = get_sha256_hash(string)
            key = bytes.fromhex(sha256[:32])

            # Find decrypt pattern
            for match in yara_scan(data, RULE_SOURCE_DECRYPT):
                try:
                    rule_str_name, str_decrypt_offset = match

                    str_decrypt_mem_offset = file_offset_to_memory_offset(pe, str_decrypt_offset)

                    encrypted_str_end = data[str_decrypt_offset + 3 : str_decrypt_offset + 7]
                    encrypted_str_start = data[str_decrypt_offset + 10 : str_decrypt_offset + 14]

                    str_end_offset = memory_address_to_file_offset(pe, str_decrypt_mem_offset + struct.unpack("i", encrypted_str_end)[0] + 7)
                    str_start_offset = memory_address_to_file_offset(pe, str_decrypt_mem_offset + struct.unpack("i", encrypted_str_start)[0] + 14)

                    encrypted_str = data[str_start_offset : str_end_offset]

                    decrypted = decrypt_aes(key, encrypted_str)

                    print(f"Decrypting string at memory offset {hex(str_decrypt_mem_offset + idaapi.get_imagebase())}, file offset {hex(str_decrypt_offset)}, result: {decrypted}")

                    idc.set_cmt(str_decrypt_mem_offset + idaapi.get_imagebase(), decrypted, 0)
                except Exception:
                    break

            print(f"AES Key String: {key_string.decode()}")
            print(f"AES Key: {key.hex()}")
        except Exception:
            continue


if __name__ == "__main__":
    main()
