import base64
import yara
import pefile
import json
import struct
import re


RULE_SOURCE = """
rule DarkCloud_Config
{
    meta:
        author = "YungBinary"
        description = "Find plain/encrypted exfil credentials in DarkCloud."
    strings:
        $smtp = {
            66 ?? ?? ?? FF
            ( 0F ?? ?? ?? ?? ?? | 75 ?? )
            C7 ?? ?? 0E 00 00 00 
            BA ?? ?? ?? ?? 
            8D ?? ?? 
            FF ?? ?? ?? ?? ??
            ( C7 | 8D )
        }

        $telegram = {
            66 ?? ?? ?? FF 
            ( 0F ?? ?? ?? ?? ?? | 75 ?? )
            C7 ?? ?? 1B 00 00 00 
            BA ?? ?? ?? ?? 
            8D ?? ?? 
            FF ?? ?? ?? ?? ??
            ( C7 | 8D )
        }

        $ftp = {
            66 ?? ?? ?? FF
            ( 0F ?? ?? ?? ?? ?? | 75 ?? )
            C7 ?? ?? 08 00 00 00 
            BA ?? ?? ?? ?? 
            8D ?? ?? 
            FF ?? ?? ?? ?? ??
            ( C7 | 8D )
        }

        $http = {
            66 ?? ?? ?? FF 
            ( 0F ?? ?? ?? ?? ?? | 75 ?? )
            C7 ?? ?? 17 00 00 00 
            BA ?? ?? ?? ??
            8D ?? ?? 
            FF ?? ?? ?? ?? ??
            ( C7 | 8D )
        }

    condition:
        $smtp and $telegram and $ftp and $http
}
"""

class VB6Rnd:
    def __init__(self):
        self.seed = 0x395886

    def randomize(self, seed: float) -> int:
        bits = struct.unpack('>Q', struct.pack('>d', seed))[0]
        n = (bits >> 32) & 0xFFFFFFFF  # Upper 32 bits
        result = ((n << 8) ^ (n >> 8)) & 0xFFFF00
        # Preserve low byte from existing seed
        self.seed = result | (self.seed & 0xFF)

    def rnd(self):
        self.seed = (0xFFC39EC3 - (self.seed * 0x2BC03)) & 0xFFFFFF
        rnd_value = self.seed / 16777216.0
        return round(rnd_value, 7)


def numeric_password(password: str) -> int:
    value = 0
    shift1 = 0
    shift2 = 0
    for i in range(len(password)):
        ch = ord(password[i])
        value ^= (ch * (2 ** shift1))
        value ^= (ch * (2 ** shift2))
        shift1 = (shift1 + 7) % 19
        shift2 = (shift2 + 13) % 23

    return value


def decrypt_string(from_text_hex: str, password: str) -> str:
    MIN_ASC = 32
    MAX_ASC = 126
    NUM_ASC = MAX_ASC - MIN_ASC + 1

    data = bytes.fromhex(from_text_hex)
    seed = numeric_password(password)
    vb_rng = VB6Rnd()
    vb_rng.randomize(float(seed))

    result = []
    for b in data:
        ch = b
        if MIN_ASC <= b <= MAX_ASC:
            ch = ch - MIN_ASC
            char_offset = int((NUM_ASC + 1) * vb_rng.rnd())
            code = (b - MIN_ASC - char_offset) % NUM_ASC
            code += MIN_ASC
            result.append(chr(code))

    return "".join(result)


def is_ciphertext(b: bytes) -> bool:
    return (
        len(b) % 2 == 0
        and all(c in b"0123456789ABCDEF" for c in b)
    )


def yara_scan_generator(raw_data, rule_source):
    yara_rules = yara.compile(source=rule_source)
    matches = yara_rules.match(data=raw_data)

    for match in matches:
        for block in match.strings:
            for instance in block.instances:
                yield instance.offset, block.identifier


def extract_config(data):
    pe = pefile.PE(data=data, fast_load=True)
    image_base = pe.OPTIONAL_HEADER.ImageBase
    config_dict = {}

    for offset, identifier in yara_scan_generator(data, RULE_SOURCE):
        offset = offset + 15 if data[offset + 5] == 0x75 else offset + 19
        try:
            if identifier == "$smtp":
                email_to_rva = struct.unpack("i", data[offset : offset + 4])[0]
                email_to = pe.get_string_u_at_rva(email_to_rva - image_base)
                email_from = b''
                host = b''
                password = b''
                port = ''

                if is_ciphertext(email_to):
                    key_rva = struct.unpack("i", data[offset + 50 : offset + 54])[0]
                    key = pe.get_string_u_at_rva(key_rva - image_base).decode()
                    
                    email_to = decrypt_string(email_to.decode(), key).encode()
    
                    email_from_rva = struct.unpack("i", data[offset + 117 : offset + 121])[0]
                    email_from = pe.get_string_u_at_rva(email_from_rva - image_base)
                    email_from = decrypt_string(email_from.decode(), key).encode()

                    password_rva = struct.unpack("i", data[offset + 234 : offset + 238])[0]
                    password = pe.get_string_u_at_rva(password_rva - image_base)
                    password = decrypt_string(password.decode(), key).encode()
                    
                    host_rva = struct.unpack("i", data[offset + 351 : offset + 355])[0]
                    host = pe.get_string_u_at_rva(host_rva - image_base)
                    host = decrypt_string(host.decode(), key).encode()

                    port_rva = struct.unpack("i", data[offset + 468 : offset + 472])[0]
                    port = pe.get_string_u_at_rva(port_rva - image_base)
                    port = decrypt_string(port.decode(), key)

                else:
                    if not email_to or email_to == b'@StrReceiver':
                        continue

                    email_from_rva = struct.unpack("i", data[offset + 21 : offset + 25])[0]
                    email_from = pe.get_string_u_at_rva(email_from_rva - image_base)

                    password_rva = struct.unpack("i", data[offset + 42 : offset + 46])[0]
                    password = pe.get_string_u_at_rva(password_rva - image_base)
                    
                    host_rva = struct.unpack("i", data[offset + 63 : offset + 67])[0]
                    host = pe.get_string_u_at_rva(host_rva - image_base)

                    port = str(struct.unpack("i", data[offset + 86 : offset + 90])[0])

                if email_to and email_from and host and password and port:
                    config_dict = {
                        "raw": {
                            "Type": "SMTP",
                            "Host": host.decode(),
                            "Port": port,
                            "From Address": email_from.decode(),
                            "To Address": email_to.decode(),
                            "Password": password.decode()
                        },
                        "CNCs": [f"smtp://{host.decode()}:{port}"]
                    }

                    break
    
            elif identifier == "$telegram":
                token_rva = struct.unpack("i", data[offset : offset + 4])[0]
                token = pe.get_string_u_at_rva(token_rva - image_base)
                chat_id = b''

                if is_ciphertext(token):
                    key_rva = struct.unpack("i", data[offset + 50 : offset + 54])[0]
                    key = pe.get_string_u_at_rva(key_rva - image_base).decode()
                    
                    token = decrypt_string(token.decode(), key).encode()
                    chat_id_rva = struct.unpack("i", data[offset + 117 : offset + 121])[0]
                    chat_id = pe.get_string_u_at_rva(chat_id_rva - image_base)
                    chat_id = decrypt_string(chat_id.decode(), key).encode()

                else:

                    if not token or token == b"@StrBotToken":
                        continue

                    chat_id_rva = struct.unpack("i", data[offset + 21 : offset + 25])[0]
                    chat_id = pe.get_string_u_at_rva(chat_id_rva - image_base)

                if token and chat_id:
                    config_dict = {"raw": {"Type": "Telegram"}, "CNCs": f"https://api.telegram.org/bot{token.decode()}/sendMessage?chat_id={chat_id.decode()}"}

                    break

            elif identifier == "$ftp":
                username_rva = struct.unpack("i", data[offset : offset + 4])[0]
                username = pe.get_string_u_at_rva(username_rva - image_base)
                host = b''
                password = b''

                if is_ciphertext(username):
                    key_rva = struct.unpack("i", data[offset + 50 : offset + 54])[0]
                    key = pe.get_string_u_at_rva(key_rva - image_base).decode()
                    username = decrypt_string(username.decode(), key).encode()
                    password_rva = struct.unpack("i", data[offset + 117 : offset + 121])[0]
                    password = pe.get_string_u_at_rva(password_rva - image_base)
                    password = decrypt_string(password.decode(), key).encode()
                    host_rva = struct.unpack("i", data[offset + 234 : offset + 238])[0]
                    host = pe.get_string_u_at_rva(host_rva - image_base)
                    host = decrypt_string(host.decode(), key).encode()

                else:

                    if not username or username == b"@StrFtpUser":
                        continue

                    password_rva = struct.unpack("i", data[offset + 21 : offset + 25])[0]
                    password = pe.get_string_u_at_rva(password_rva - image_base)

                    host_rva = struct.unpack("i", data[offset + 42 : offset + 46])[0]
                    host = pe.get_string_u_at_rva(host_rva - image_base)

                if username and host and password:
                    config_dict = {
                        "raw": {
                            "Type": "FTP", "Host": host.decode(), "Username": username.decode(), "Password": password.decode()},
                        "CNCs": [f"ftp://{username.decode()}:{password.decode()}@{host.decode()}"]
                    }

                    break
            
            elif identifier == "$http":
                gate_url_rva = struct.unpack("i", data[offset : offset + 4])[0]
                gate_url = pe.get_string_u_at_rva(gate_url_rva - image_base)

                if is_ciphertext(gate_url):
                    key_rva = struct.unpack("i", data[offset + 50 : offset + 54])[0]
                    key = pe.get_string_u_at_rva(key_rva - image_base).decode()
                    gate_url = decrypt_string(gate_url.decode(), key).encode()

                if not gate_url or gate_url == b"@GateUrl":
                    continue

                config_dict = {"CNCs": [gate_url.decode()]}

                break

        except Exception:
            continue

    return config_dict



if __name__ == "__main__":
    import sys

    with open(sys.argv[1], "rb") as f:
        print(json.dumps(extract_config(f.read()), indent=4))
