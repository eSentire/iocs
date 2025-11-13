import base64
import json
import pefile
import yara
import struct
import re
import ipaddress
from contextlib import suppress


DESCRIPTION = "Amatera Stealer parser"
AUTHOR = "YungBinary"

RULE_SOURCE = """
rule AmateraDecrypt
{
    meta:
        author = "YungBinary"
        description = "Find Amatera XOR key"
    strings:
        $decrypt = {
            A1 ?? ?? ?? ??                  // mov     eax, dword ptr ds:szXorKey ; "852149723"
            89 45 ??                        // mov     dword ptr [ebp+xor_key], eax
            8B 0D ?? ?? ?? ??               // mov     ecx, dword ptr ds:szXorKey+4 ; "49723"
            89 4D ??                        // mov     dword ptr [ebp+xor_key+4], ecx
            66 8B 15 ?? ?? ?? ??            // mov     dx, word ptr ds:szXorKey+8 ; "3"
            66 89 55 ??                     // mov     word ptr [ebp+xor_key+8], dx
            8D 45 ??                        // lea     eax, [ebp+xor_key]
            50                              // push    eax
            E8                              // call
        }
    condition:
        uint16(0) == 0x5A4D and $decrypt
}
"""


RULE_SOURCE_AES_KEY = """
rule AmateraAESKey
{
    meta:
        author = "YungBinary"
        description = "Find Amatera AES key"
    strings:
        $aes_key_on_stack = {
            83 EC 2C                        // sub     esp, 2Ch
            C6 45 D4 ??                     // mov     byte ptr [ebp-2Ch], ??
            C6 45 D5 ??                     // mov     byte ptr [ebp-2Bh], ??
            C6 45 D6 ??                     // mov     byte ptr [ebp-2Ah], ??
            C6 45 D7 ??                     // mov     byte ptr [ebp-29h], ??
            C6 45 D8 ??                     // mov     byte ptr [ebp-28h], ??
            C6 45 D9 ??                     // mov     byte ptr [ebp-27h], ??
            C6 45 DA ??                     // mov     byte ptr [ebp-26h], ??
            C6 45 DB ??                     // mov     byte ptr [ebp-25h], ??
            C6 45 DC ??                     // mov     byte ptr [ebp-24h], ??
            C6 45 DD ??                     // mov     byte ptr [ebp-23h], ??
            C6 45 DE ??                     // mov     byte ptr [ebp-22h], ??
            C6 45 DF ??                     // mov     byte ptr [ebp-21h], ??
            C6 45 E0 ??                     // mov     byte ptr [ebp-20h], ??
            C6 45 E1 ??                     // mov     byte ptr [ebp-1Fh], ??
            C6 45 E2 ??                     // mov     byte ptr [ebp-1Eh], ??
            C6 45 E3 ??                     // mov     byte ptr [ebp-1Dh], ??
            C6 45 E4 ??                     // mov     byte ptr [ebp-1Ch], ??
            C6 45 E5 ??                     // mov     byte ptr [ebp-1Bh], ??
            C6 45 E6 ??                     // mov     byte ptr [ebp-1Ah], ??
            C6 45 E7 ??                     // mov     byte ptr [ebp-19h], ??
            C6 45 E8 ??                     // mov     byte ptr [ebp-18h], ??
            C6 45 E9 ??                     // mov     byte ptr [ebp-17h], ??
            C6 45 EA ??                     // mov     byte ptr [ebp-16h], ??
            C6 45 EB ??                     // mov     byte ptr [ebp-15h], ??
            C6 45 EC ??                     // mov     byte ptr [ebp-14h], ??
            C6 45 ED ??                     // mov     byte ptr [ebp-13h], ??
            C6 45 EE ??                     // mov     byte ptr [ebp-12h], ??
            C6 45 EF ??                     // mov     byte ptr [ebp-11h], ??
            C6 45 F0 ??                     // mov     byte ptr [ebp-10h], ??
            C6 45 F1 ??                     // mov     byte ptr [ebp-0Fh], ??
            C6 45 F2 ??                     // mov     byte ptr [ebp-0Eh], ??
            C6 45 F3 ??                     // mov     byte ptr [ebp-0Dh], ??
            C7 45 F4 10 00 00 00            // mov     dword ptr [ebp-0Ch], 10h
        }
    condition:
        uint16(0) == 0x5A4D and $aes_key_on_stack
}
"""

DOMAIN_REGEX = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'


def yara_scan(raw_data: bytes, rule_source: str):
    yara_rules = yara.compile(source=rule_source)
    matches = yara_rules.match(data=raw_data)

    for match in matches:
        for block in match.strings:
            for instance in block.instances:
                return instance.offset


def extract_base64_strings(data: bytes, minchars: int, maxchars: int):
    """
    Generator that returns ASCII formatted base64 strings
    """
    apat = b"([A-Za-z0-9+/=]{" + str(minchars).encode() + b"," + str(maxchars).encode() + b"})\x00"
    for s in re.findall(apat, data):
        yield s.decode()


def xor_data(data, key):
    decoded = bytearray()
    for i in range(len(data)):
        decoded.append(key[i % len(key)] ^ data[i])
    return decoded


def is_public_ip(ip):
    try:
        # This will raise a ValueError if the IP format is incorrect
        ip_obj = ipaddress.ip_address(ip.decode())
        if ip_obj.is_private:
            return False
        return True
    except Exception:
        return False


def is_valid_domain(data):
    try:
        if re.fullmatch(DOMAIN_REGEX, data.decode()):
            return True
        return False
    except Exception:
        return False


def extract_config(data):
    """
    Extract Amatera malware configuration.
    """
    config_dict = {}

    with suppress(Exception):
        pe = pefile.PE(data=data)
        image_base = pe.OPTIONAL_HEADER.ImageBase

        # Identify XOR key decryption routine and extract key
        offset = yara_scan(data, RULE_SOURCE)
        if not offset:
            return config_dict
        key_str_va = struct.unpack('i', data[offset + 1: offset + 5])[0]
        key_str = pe.get_string_at_rva(key_str_va - image_base, max_length=20) + b'\x00'

        # Extract AES 256 key
        aes_key_offset = yara_scan(data, RULE_SOURCE_AES_KEY)
        aes_key = bytearray()
        if aes_key_offset:
            aes_block = data[aes_key_offset : aes_key_offset + 131]
            for i in range(0, len(aes_block) - 4, 4):
                aes_key.append(aes_block[i+6])

        # Handle each base64 string -> decode -> decrypt with XOR key
        for b64_str in extract_base64_strings(data, 8, 20):
            try:
                decoded = base64.b64decode(b64_str, validate=True)
                decrypted = xor_data(decoded, key_str)
                if not is_public_ip(decrypted) and not is_valid_domain(decrypted):
                    continue

                config_dict["CNCs"] = [f"https://{decrypted.decode()}"]

                if aes_key:
                    config_dict["cryptokey"] = aes_key.hex()
                    config_dict["cryptokey_type"] = "AES"

                return config_dict
            except Exception:
                continue

    return config_dict


if __name__ == "__main__":
    import sys

    with open(sys.argv[1], "rb") as f:
        config_json = json.dumps(extract_config(f.read()), indent=4)
        print(config_json)
