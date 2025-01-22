import base64
import re
import pefile
import yara
import json
import struct

RULE_SOURCE_BUILD_ID = """rule LummaBuildId
{
    meta:
        author = "YungBinary"
    strings:
        $chunk_1 = {
            8B ( 1D | 0D | 15 ) [4]
            C7 [5-10]
            C7 [5-10]
            C7 [5-10]
            C7 [5-10]
            C7 [5-10]
            C7 [5-10]
            C7 [5-10]
            C7
        }
    condition:
        $chunk_1
}"""

RULE_SOURCE_LUMMA = """rule LummaConfig
{
    meta:
        author = "YungBinary"
    strings:
        $chunk_1 = { 32 1D 30 F9 48 77 82 5A 3C BF 73 7F DD 4F 15 75 }
    condition:
        $chunk_1
}"""


def yara_scan_generator(raw_data, rule_source):
    yara_rules = yara.compile(source=rule_source)
    matches = yara_rules.match(data=raw_data)

    for match in matches:
        for block in match.strings:
            for instance in block.instances:
                yield instance.offset


def yara_scan(raw_data, rule_source):
    yara_rules = yara.compile(source=rule_source)
    matches = yara_rules.match(data=raw_data)

    for match in matches:
        for block in match.strings:
            for instance in block.instances:
                return instance.offset


def is_base64(s):
    pattern = re.compile("^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{4}|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)$")
    if not s or len(s) < 1:
        return False
    else:
        return pattern.match(s)


def extract_strings(data, minchars):
    endlimit = b"8192"
    apat = b"([\x20-\x7e]{" + str(minchars).encode() + b"," + endlimit + b"})\x00"
    strings = [string.decode() for string in re.findall(apat, data)]
    return strings


def get_base64_strings(str_list):
    base64_strings = []
    for s in str_list:
        if is_base64(s):
            base64_strings.append(s)
    return base64_strings


def get_rdata(pe, data):
    rdata = None
    section_idx = 0
    for section in pe.sections:
        if section.Name == b".rdata\x00\x00":
            rdata = pe.sections[section_idx].get_data()
            break
        section_idx += 1
    return rdata


def xor_data(data, key):
    decoded = bytearray()
    for i in range(len(data)):
        decoded.append(data[i] ^ key[i % len(data)])
    return decoded


def contains_non_printable(byte_array):
    for byte in byte_array:
        if not chr(byte).isprintable():
            return True
    return False


def mask32(x):
    return x & 0xFFFFFFFF


def add32(x, y):
    return mask32(x + y)


def left_rotate(x, n):
    return mask32(x << n) | (x >> (32 - n))


def quarter_round(block, a, b, c, d):
    block[a] = add32(block[a], block[b])
    block[d] ^= block[a]
    block[d] = left_rotate(block[d], 16)
    block[c] = add32(block[c], block[d])
    block[b] ^= block[c]
    block[b] = left_rotate(block[b], 12)
    block[a] = add32(block[a], block[b])
    block[d] ^= block[a]
    block[d] = left_rotate(block[d], 8)
    block[c] = add32(block[c], block[d])
    block[b] ^= block[c]
    block[b] = left_rotate(block[b], 7)


def chacha20_permute(block):
    for doubleround in range(10):
        quarter_round(block, 0, 4, 8, 12)
        quarter_round(block, 1, 5, 9, 13)
        quarter_round(block, 2, 6, 10, 14)
        quarter_round(block, 3, 7, 11, 15)
        quarter_round(block, 0, 5, 10, 15)
        quarter_round(block, 1, 6, 11, 12)
        quarter_round(block, 2, 7, 8, 13)
        quarter_round(block, 3, 4, 9, 14)


def words_from_bytes(b):
    assert len(b) % 4 == 0
    return [int.from_bytes(b[4 * i : 4 * i + 4], "little") for i in range(len(b) // 4)]


def bytes_from_words(w):
    return b"".join(word.to_bytes(4, "little") for word in w)


def chacha20_block(key, nonce, blocknum):
    constant_words = words_from_bytes(b"expand 32-byte k")
    key_words = words_from_bytes(key)
    nonce_words = words_from_bytes(nonce)

    original_block = [
        constant_words[0],  constant_words[1],  constant_words[2],  constant_words[3],
        key_words[0],       key_words[1],       key_words[2],       key_words[3],
        key_words[4],       key_words[5],       key_words[6],       key_words[7],
        mask32(blocknum),   nonce_words[0],     nonce_words[1],     nonce_words[2],
    ]

    permuted_block = list(original_block)
    chacha20_permute(permuted_block)
    for i in range(len(permuted_block)):
        permuted_block[i] = add32(permuted_block[i], original_block[i])
    return bytes_from_words(permuted_block)


def chacha20_stream(key, nonce, length, blocknum):
    output = bytearray()
    while length > 0:
        block = chacha20_block(key, nonce, blocknum)
        take = min(length, len(block))
        output.extend(block[:take])
        length -= take
        blocknum += 1
    return output


def chacha20_xor(message, key, nonce, counter):
    message_len = len(message)
    key_stream = chacha20_stream(key, nonce, message_len, counter)

    xor_key = bytearray()
    for i in range(message_len):
        xor_key.append(message[i] ^ key_stream[i])

    return xor_key


def extract_c2_domain(data):
    pattern = rb"([\w-]+\.[\w]+)\x00"
    match = re.search(pattern, data)
    if match:
        return match.group(1)


def find_encrypted_c2_blocks(data):
    pattern = rb'(.{128})\x00'
    for match in re.findall(pattern, data, re.DOTALL):
        yield match


def get_build_id(pe, data):
    build_id = ""
    image_base = pe.OPTIONAL_HEADER.ImageBase
    for offset in yara_scan_generator(data, RULE_SOURCE_BUILD_ID):
        try:
            build_id_data_rva = struct.unpack('i', data[offset + 2 : offset + 6])[0]
            build_id_dword_offset = pe.get_offset_from_rva(build_id_data_rva - image_base)
            build_id_dword_rva = struct.unpack('i', data[build_id_dword_offset : build_id_dword_offset + 4])[0]
            build_id_offset = pe.get_offset_from_rva(build_id_dword_rva - image_base)
            build_id = pe.get_string_from_data(build_id_offset, data)
            if not contains_non_printable(build_id):
                build_id = pe.get_string_from_data(build_id_offset, data).decode()
                break
        except Exception:
            continue
    return build_id


def extract_config(data):
    config_dict = {"C2": []}

    # try to load as a PE
    pe = None
    image_base = None
    try:
        pe = pefile.PE(data=data)
        image_base = pe.OPTIONAL_HEADER.ImageBase
    except Exception:
        pass


    offset = yara_scan(data, RULE_SOURCE_LUMMA)
    if offset:
        key = data[offset + 16 : offset + 48]
        nonce = b"\x00\x00\x00\x00" + data[offset + 48 : offset + 56]
        rvas = []

        for i in range(9):
            try:
                start_offset = offset + 56 + (i * 4)
                end_offset = start_offset + 4
                c2_dword_rva = struct.unpack('i', data[start_offset : end_offset])[0]
                if pe:
                    c2_dword_offset = pe.get_offset_from_rva(c2_dword_rva - image_base)
                else:
                    c2_dword_offset = c2_dword_rva - image_base

                c2_encrypted = data[c2_dword_offset : c2_dword_offset + 0x80]
                counters = [0, 2, 4, 6, 8, 10, 12, 14, 16]
                for counter in counters:
                    decrypted = chacha20_xor(c2_encrypted, key, nonce, counter)
                    c2 = extract_c2_domain(decrypted)
                    if c2 is not None and len(c2) > 10:
                        config_dict["C2"].append(c2.decode())
                        break

            except Exception:
                continue


    # If no C2s try with version prior to Jan 21, 2025
    if not config_dict["C2"]:

        try:
            if pe is not None:
                rdata = get_rdata(pe, data)
                if rdata is not None:
                    strings = extract_strings(rdata, 44)
                else:
                    strings = extract_strings(data, 44)
            else:
                strings = extract_strings(data, 44)

            base64_strings = get_base64_strings(strings)
            for base64_str in base64_strings:
                try:
                    decoded_bytes = base64.b64decode(base64_str, validate=True)
                    encoded_c2 = decoded_bytes[32:]
                    xor_key = decoded_bytes[:32]
                    decoded_c2 = xor_data(encoded_c2, xor_key)

                    if not contains_non_printable(decoded_c2):
                        config_dict["C2"].append(decoded_c2.decode())
                except Exception:
                    continue

        except Exception:
            return

    if config_dict["C2"] and pe is not None:
        # If found C2 servers try to find build ID
        build_id = get_build_id(pe, data)
        if build_id:
            config_dict["Build ID"] = build_id

    return config_dict


if __name__ == "__main__":
    import sys

    with open(sys.argv[1], "rb") as f:
        print(json.dumps(extract_config(f.read()), indent=4))
