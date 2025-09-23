import pefile
import struct
import idc
import idautils
import idaapi


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


def is_possible_key_string(b: bytes) -> bool:
    if len(b) < 10:
        return False

    return all(c in b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ" for c in b)


def get_edx_string_before_vbaStrCopy():
    results = []
    target_ea = idc.get_name_ea_simple("__imp___vbaStrCopy")
    if target_ea == idc.BADADDR:
        idaapi.msg("[-] __imp___vbaStrCopy not found\n")
        return results

    for ref in idautils.XrefsTo(target_ea):
        call_ea = ref.frm
        if idc.print_insn_mnem(call_ea) != "call":
            continue

        # Get edx operand address
        cur = call_ea - 8

        # Ensure mnemonic is mov
        mnem = idc.print_insn_mnem(cur)
        if mnem != "mov":
            continue
        
        # Ensure first operand is a register
        if idc.get_operand_type(cur, 0) != idc.o_reg:
            continue
        
        # Ensure first operand is named edx
        if idc.print_operand(cur, 0).lower() != "edx":
            continue

        # Ensure second operand is a constant
        if idc.get_operand_type(cur, 1) != idc.o_imm:
            continue

        # Get the operand value as a UTF 16 string
        edx_ea = idc.get_operand_value(cur, 1)
        edx_str = idc.get_strlit_contents(edx_ea, -1, idc.STRTYPE_C_16)
        if not edx_str or not is_ciphertext(edx_str):
            continue

        # Walk forwards to find probable key strings
        cur = call_ea
        key_strs = []
        key_eas = []
        while True:
            cur = idc.next_head(cur)
            if cur == idc.BADADDR:
                break
            
            mnem = idc.print_insn_mnem(cur)
            if mnem != "push":
                continue

            op_type = idc.get_operand_type(cur, 0)
            if op_type != idc.o_imm:
                continue

            key_address = idc.get_operand_value(cur, 0)
            string = idc.get_strlit_contents(key_address, -1, idc.STRTYPE_C_16)

            if string and is_possible_key_string(string):
                key_strs.append(string)
                key_eas.append(cur)
                if len(key_strs) > 1:
                    break

        if key_strs:
            results.append({
                "call_ea": call_ea,
                "edx_ea": edx_ea,
                "edx_str": edx_str,
                "key_eas": key_eas,
                "key_strs": key_strs
            })

    return results


hits = get_edx_string_before_vbaStrCopy()
for h in hits:
    decrypted_strings = []
    for key_str in h['key_strs']:
        decrypted = decrypt_string(h['edx_str'].decode(), key_str.decode())
        print(f"Call at {h['call_ea']:08X}, possible decrypted value: '{decrypted}'")
        decrypted_strings.append(decrypted)
    
    idc.set_cmt(h['call_ea'], "\n".join(decrypted_strings), 0)
