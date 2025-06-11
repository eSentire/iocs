"""
Author: YungBinary
Description: Decrypt C2 and strings from DeerStealer minidump and comment in IDA Pro
# Command to take a minidump in x64dbg:
    minidump C:/Path/To/Minidump.dmp
# Take note of the base address where DeerStealer is in memory
# Use this base address to rebase the binary in IDA Pro:
#   Edit -> Segments -> Rebase program
# Install dumpulator, yara, construct:
#     > pip install dumpulator yara-python construct
# (Optional) Install older version of setuptools to
# ignore deprecation warnings in unicorn:
#     > pip install setuptools==66.1.1
"""

# Set your minidump file path here
MINIDUMP_FILEPATH = 'C:\\path\\to\\DeerStealer.dmp'


from dumpulator import Dumpulator
import yara
import struct
import json
from collections import defaultdict
from construct import (
    Struct, Bytes, Int16ul, Const, Construct, ListContainer,
    this, StreamError
)
from collections import Counter
import io
import sys

# Function in the event the script is being run outside of IDA
try:
    import idc
except:
    pass



ENCRYPTED_STR_STRUCT_1 = Struct(
    "blob_id"   / Bytes(2),
    "size_blob_1" / Int16ul,
    "size_blob_2" / Int16ul,
    "unknown_2"   / Bytes(2),
    "blob_1"      / Bytes(this.size_blob_1),
    "blob_2"      / Bytes(this.size_blob_2),
)

ENCRYPTED_STR_STRUCT_2 = Struct(
    "blob_id"   / Bytes(2),
    "size_blob_2" / Int16ul,
    "unknown_2"   / Bytes(2),
    "size_blob_1" / Int16ul,
    "blob_1"      / Bytes(this.size_blob_1),
    "blob_2"      / Bytes(this.size_blob_2),
)


class GlobalFallbackParser(Construct):
    def _parse(self, stream, context, path):
        payload_bytes = stream.read(context.payload_size)
        substream = io.BytesIO(payload_bytes)
        
        # --- ATTEMPT 1: Parse ENTIRE payload as struct_1 sequence ---
        #print("\n>>> Starting Attempt 1: Parsing payload as a sequence of ONLY struct_1...")
        try:
            items = ListContainer()
            while substream.tell() < len(payload_bytes):
                parsed_item = ENCRYPTED_STR_STRUCT_1.parse_stream(substream)
                items.append(parsed_item)
            
            #print("    SUCCESS: Entire payload parsed as a sequence of struct_1.")
            return items
        except StreamError as e1:
            #print(f"    FAILURE: Attempt 1 failed. Reason: {e1}")
            pass

        # --- ATTEMPT 2: "Complete Restart" with explicit rewind ---
        #print("\n>>> Starting Attempt 2: Rewinding completely and parsing payload as a sequence of ONLY struct_2...")
        substream.seek(0)
        
        try:
            items = ListContainer()
            while substream.tell() < len(payload_bytes):
                parsed_item = ENCRYPTED_STR_STRUCT_2.parse_stream(substream)
                items.append(parsed_item)

            #print("    SUCCESS: Entire payload parsed as a sequence of struct_2.")
            return items
        except StreamError as e2:
            print(f"    FAILURE: Attempt 2 also failed. Reason: {e2}")
            raise e2

    def _build(self, obj, stream, context, path):
        raise NotImplementedError("Building not implemented")


FinalMessageStruct = Struct(
    "payload_size" / Int16ul,
    "magic_header" / Const(b'\x00\x00\x00\x00\x00\x40'),
    "payload_items" / GlobalFallbackParser()
)

RULE_SOURCE_DECRYPT_ROUTINE = """
rule DeerStealerDecrypt
{
    meta:
        author = "YungBinary"
        description = "Find C2 decryption routine"
    strings:
        $decrypt = {
            48 8B 95 [4]
            48 8B 85 [4]
            48 8B 48 10
            48 83 C1 08
            49 B8 [8]
            48 83 EC 20
            E8
        }
    condition:
        uint16(0) == 0x5A4D and $decrypt
}
"""

RULE_SOURCE_ENCRYPTED_C2 = """
rule DeerStealerEncryptedC2
{
    meta:
        author = "YungBinary"
        description = "Find encrypted c2"
    strings:
        $encrypted_c2 = { ?? 00 00 00 00 00 00 40 }
    condition:
        uint16(0) == 0x5A4D and $encrypted_c2
}
"""

RULE_SOURCE_ENCRYPTED_STRING = """
rule DeerStealerEncryptedString
{
    meta:
        author = "YungBinary"
        description = "Used to find the start of encrypted strings in .rdata"
    strings:
        $chunk = {
            48 83 C4 20
            48 89 45 ??
            48 8B 05 ?? ?? ?? ??
            48 89 [1-2]
            48 8B 05 ?? ?? ?? ??
        }
    condition:
        uint16(0) == 0x5A4D and $chunk
}
"""

RULE_SOURCE_DECRYPT_STRINGS_ROUTINE = """
rule DeerStealerDecryptStringsRoutine
{
    meta:
        author = "YungBinary"
        description = "Find string decryption routine"
    strings:
        $decrypt_bytes = {
            48 8B 08
            48 8B 50 10
            4C 8B 02
            48 63 50 08
            48 83 C4 28
            E9
        }
    condition:
        uint16(0) == 0x5A4D and $decrypt_bytes
}
"""

RULE_SOURCE_DECRYPT_STRING_CALL = """
rule DeerStealerDecryptStringCall
{
    meta:
        author = "YungBinary"
        description = "Detects DeerStealer string decryption function calls."

    strings:

        // Sequence 1: lea rcx OR mov, [rbp+disp8]; sub rsp, 0x20; call <rel>
        $seq_lea_disp8_direct = { 66 C7 45 ?? ?? ?? 48 8D 4D ?? 48 83 EC 20 E8 }

        // Sequence 2: lea rcx, [rbp+disp32]; sub rsp, 0x20; call <rel>
        $seq_lea_disp32 = { 66 C7 85 ?? ?? ?? ?? ?? ?? 48 8D 8D ?? ?? ?? ?? 48 83 EC 20 E8 }

        // Sequence 3: mov word ptr [rcx], imm16; sub rsp, 0x20; call <rel>
        $seq_mov_imm16 = { 48 89 05 ?? ?? ?? ?? 66 C7 01 ?? ?? 48 83 EC 20 E8 }

        // Sequence 4: mov [rcx], ax; sub rsp, 0x20; call
        $seq_mov_ax = { 66 B8 ?? ?? 66 35 ?? ?? 66 89 [1-12] 48 83 EC 20 E8 }

        // Sequence 5: mov; lea rcx; call
        $seq_mov_var = { 66 C7 84 ?? ?? ?? ?? ?? ?? ?? 48 8D 8C ?? ?? ?? ?? ?? E8 }

        // Sequence 6: mov word ptr [rcx], ????h, sub rsp, 0x20, call
        $seq_direct = { 66 C7 01 ?? ?? 48 83 EC 20 E8 }

    condition:
        any of them
}
"""


def extract_config(dump_file):
    """
    This function will be run in a separate process
    and serves to parse the minidump with Dumpulator
    and extract the C2 and strings.
    """

    dp = Dumpulator(dump_file, quiet=True)
    rules_encrypted_strings_egg = yara.compile(source=RULE_SOURCE_ENCRYPTED_STRING)
    rules_decrypt = yara.compile(source=RULE_SOURCE_DECRYPT_ROUTINE)
    rules_decrypt_strings = yara.compile(source=RULE_SOURCE_DECRYPT_STRINGS_ROUTINE)
    rules_c2 = yara.compile(source=RULE_SOURCE_ENCRYPTED_C2)
    rules_decrypt_string_call = yara.compile(source=RULE_SOURCE_DECRYPT_STRING_CALL)

    c2_url = ""
    decryption_routine_c2 = None
    decryption_routine_strings = None
    config_dict = {"C2": "", "Strings": {}}

    # Loop through memory regions in minidump
    for region in dp.memory._regions:
        base = region.start
        size = region.size
        try:
            data = dp.read(base, size)

            # Find C2 decryption routine
            matches = rules_decrypt.match(data=data)
            if not matches:
                continue

            key = None
            for match in matches:
                for block in match.strings:
                    for instance in block.instances:
                        displacement_offset = struct.unpack('<i', data[instance.offset + 37 : instance.offset + 41])[0]
                        key = struct.unpack('<q', data[instance.offset + 24 : instance.offset + 32])[0]
                        decryption_routine_c2 = instance.offset + 41 + base + displacement_offset
                        break

            # Find string decryption routine
            matches = rules_decrypt_strings.match(data=data)
            if not matches:
                continue
            for match in matches:
                for block in match.strings:
                    for instance in block.instances:
                        displacement_offset = struct.unpack('<i', data[instance.offset + 19 : instance.offset + 23])[0]
                        decryption_routine_strings = instance.offset + 23 + base + displacement_offset
                        break

            if decryption_routine_c2:
                # Find and decrypt encrypted C2
                matches = rules_c2.match(data=data)
                for match in matches:
                    for block in match.strings:
                        for instance in block.instances:
                            try:
                                encrypted_size = data[instance.offset]
                                if not encrypted_size:
                                    continue
                                encrypted_data_start = instance.offset + 8
                                encrypted_data = data[encrypted_data_start : encrypted_data_start + encrypted_size]
                                
                                input_addr = dp.allocate(encrypted_size)
                                dp.write(input_addr, encrypted_data)
                                dp.call(decryption_routine_c2, [input_addr, encrypted_size, key])
                                decrypted_str = dp.read_str(input_addr)
                                if decrypted_str.startswith('http'):
                                    c2_url = decrypted_str
                                    ea = instance.offset + base
                                    print(f'Found encrypted C2 at: {hex(ea)}, C2 decryption routine at: {hex(decryption_routine_c2)}, decrypted: {c2_url}')
                                    if 'idc' in sys.modules:
                                        idc.set_cmt(ea, c2_url, 0)
                                    break
                            except:
                                continue
            
            if decryption_routine_strings:
                # Parse the encrypted string config
                matches = rules_encrypted_strings_egg.match(data=data)
                for match in matches:
                    for block in match.strings:
                        try:
                            for instance in block.instances:
                                start = instance.offset + instance.matched_length - 4
                                end = instance.offset + instance.matched_length
                                displacement_offset = struct.unpack('<i', data[start : end])[0]
                                # Using the displacement offset, find the egg
                                egg_start = instance.offset + instance.matched_length + displacement_offset - 8
                                egg_end = egg_start + 2
                                egg = data[egg_start: egg_end]
                                # Using the egg find the start of encrypted strings structure
                                encrypted_data_offset = egg_start + 16
                                egg2 = data[encrypted_data_offset : encrypted_data_offset + 2]
                                if egg != egg2:
                                    continue

                                #print(f"Confirmed egg: {egg.hex()} at offset: {hex(encrypted_data_offset)}")

                                encrypted_data_size = int.from_bytes(egg, byteorder='little')
                                #print(f"Encrypted data size: {encrypted_data_size}")
                                encrypted_data = data[encrypted_data_offset : encrypted_data_offset + encrypted_data_size + 8]
                                parsed_data = FinalMessageStruct.parse(encrypted_data)
                                
                                suffix_candidates = []
                                for item in parsed_data.payload_items:
                                    if item.size_blob_1 >= 8: suffix_candidates.append(item.blob_1[-8:])
                                    if item.size_blob_2 >= 8: suffix_candidates.append(item.blob_2[-8:])
                                

                                suffix_counts = Counter(suffix_candidates)
                                most_common_list = suffix_counts.most_common(1)
                                key_bytes = None
                                key = None
                                if most_common_list:
                                    key_bytes, count = most_common_list[0]
                                    key = int.from_bytes(key_bytes, byteorder='little')
                                    for i, item in enumerate(parsed_data.payload_items):
                                        if item.blob_1.endswith(key_bytes):
                                            encrypted_str_size = item.size_blob_2
                                            input_addr = dp.allocate(encrypted_str_size)
                                            dp.write(input_addr, item.blob_2)
                                            dp.call(decryption_routine_strings, [input_addr, encrypted_str_size, key])
                                            decrypted_str = dp.read_str(input_addr)
                                            config_dict["Strings"][item.blob_id.hex()] = decrypted_str

                                else:
                                    print("Could not identify key to decrypt strings.")


                        except Exception as e:
                            print(e)
                            continue
        
                # Find references to decryption routine call
                matches = rules_decrypt_string_call.match(data=data)
                for match in matches:
                    for block in match.strings:
                        for instance in block.instances:
                            word_offset = None
                            
                            if block.identifier == '$seq_mov_ax':
                                xor_operand_1 = int.from_bytes(data[instance.offset + 2 : instance.offset + 4], byteorder='little')
                                xor_operand_2 = int.from_bytes(data[instance.offset + 6 : instance.offset + 8], byteorder='little')
                                string_id = (xor_operand_1 ^ xor_operand_2) & 0xFFFF
                                string_id = string_id.to_bytes(2, byteorder='little').hex()
                                if string_id in config_dict["Strings"]:
                                    ea = instance.offset + base
                                    print(f'Found string decryption at: {hex(ea)}, decrypted: {config_dict["Strings"][string_id]}')
                                    if 'idc' in sys.modules:
                                        idc.set_cmt(ea, config_dict["Strings"][string_id], 0)
                                continue
                            elif block.identifier == '$seq_lea_disp8':
                                # The WORD (imm16) is at the 5th byte (index 4)
                                word_offset = instance.offset + 4

                            elif block.identifier == '$seq_mov_imm16':
                                # The WORD (imm16) is at the 10th byte
                                word_offset = instance.offset + 10
                            
                            elif block.identifier == '$seq_lea_disp8_direct':
                                # The WORD (imm16) is at the 5th byte (index 4)
                                word_offset = instance.offset + 4

                            elif block.identifier == '$seq_lea_disp32':
                                # The WORD (imm16) is at the 7th byte
                                word_offset = instance.offset + 7
                            
                            elif block.identifier == '$seq_mov_var':
                                # The WORD (imm16) is at the 8th byte
                                word_offset = instance.offset + 8

                            elif block.identifier == '$seq_direct':
                                # The WORD (imm16) is at the 4th byte
                                word_offset = instance.offset + 3

                            
                            # Map the word to the string id and set comment in IDA Pro
                            if word_offset is not None:
                                # Read the 2-byte WORD from the calculated offset
                                string_id = data[word_offset : word_offset + 2].hex()
                                if string_id in config_dict["Strings"]:
                                    ea = base + word_offset + 2
                                    print(f'Found string decryption at: {hex(ea)}, rule: {block.identifier}, decrypted: {config_dict["Strings"][string_id]}')
                                    if 'idc' in sys.modules:
                                        idc.set_cmt(ea, config_dict["Strings"][string_id], 0)
                                    word_offset = None



        except Exception as e:
            #print(e)
            continue
   
    
    if not c2_url:
        print("Could not find C2 URL!")
        return

    config_dict["C2"] = c2_url
    print(json.dumps(config_dict, indent=4))


def main():
    extract_config(MINIDUMP_FILEPATH)



if __name__ == "__main__":
    main()
