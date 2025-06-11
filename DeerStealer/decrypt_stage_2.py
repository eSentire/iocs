import yara
import pefile
import struct
import idc
import idaapi
import os

"""
Author: YungBinary
Description: Use in IDA Pro with first stage of HijackLoader loaded.
The first stage is typically a DLL file that has a patched CRT.
"""


# Specify the path to the encrypted second stage shellcode here
STAGE_2_PATH = '/home/lab/Desktop/Malware/HijackLoader/ProgramData/AppDownload/Bairrout.xd'


RULE_SOURCE_OFFSET = """rule HijackLoaderOffset
{
    meta:
        author = "Yung Binary"

    strings:
		$offset_pattern = {
			FF D0
			8B ?? ?? ?? ?? ?? ??
			4C 01 ??
			8B 05 ?? ?? ?? ??
			89 C0
			49 01 ??
			41 8B ?? ??
			41 8B ?? ?? 04
			49 8D ?? ?? 08
			85 ??
			74 ??
		}

    condition:
        $offset_pattern
}
"""


def yara_scan(raw_data, rule_source):
    yara_rules = yara.compile(source=rule_source)
    matches = yara_rules.match(data=raw_data)

    for match in matches:
        for block in match.strings:
            for instance in block.instances:
                yield block.identifier, instance.offset


def file_offset_to_memory_offset(pe, file_offset):
    for section in pe.sections:
        section_start = section.PointerToRawData
        section_end = section_start + section.SizeOfRawData
        if section_start <= file_offset < section_end:
            memory_offset = section.VirtualAddress + (file_offset - section_start)
            return memory_offset


def memory_address_to_file_offset(pe, memory_address):
    for section in pe.sections:
        section_va = section.VirtualAddress
        section_start = section.PointerToRawData
        if section_va <= memory_address < section_va + section.SizeOfRawData:
            file_offset = section_start + (memory_address - section_va)
            return file_offset


loaded_bin_path = idc.get_input_file_path()

with open(loaded_bin_path, "rb") as f:
    data = f.read()

pe = pefile.PE(data=data, fast_load=False)
image_base = idaapi.get_imagebase()


# Find offset for start of encrypted header
file_offset = 0
for match in yara_scan(data, RULE_SOURCE_OFFSET):
    try:
        rule_str_name, match_offset = match
        displacement_value = data[match_offset + 14 : match_offset + 18]
        match_mem_offset = file_offset_to_memory_offset(pe, match_offset)
        dword_offset = memory_address_to_file_offset(pe, match_mem_offset + struct.unpack("i", displacement_value)[0] + 18)
        # Offset into encrypted stage 2
        file_offset = struct.unpack("<I", data[dword_offset: dword_offset + 4])[0]
        print(f"Found second stage's file offset {hex(file_offset)} at {hex(match_mem_offset + image_base)}")
    except Exception as e:
        print(e)
        continue

if not file_offset:
    print("Unable to find encrypted file offset.")


decrypted_bytes = b''

with open(STAGE_2_PATH, 'rb') as f:
    f.read(file_offset)
    encrypted_size = int.from_bytes(f.read(4), byteorder='little')
    print(f"Second stage encrypted size: {hex(encrypted_size)}")
    constant = int.from_bytes(f.read(4), byteorder='little')
    print(f"Decryption constant: {hex(constant)}")

    encrypted_chunk = f.read(4)
    while encrypted_chunk:
        decrypted = (int.from_bytes(encrypted_chunk, byteorder='little') + constant) & 0xFFFFFFFF
        # Convert to big endian
        decrypted = decrypted.to_bytes(4, byteorder='little')
        decrypted_bytes += decrypted
        encrypted_chunk = f.read(4)

# Handle the decrypted payload's file header
initial_block_end_offset = int(decrypted_bytes[0])
oep_rva_offset = initial_block_end_offset + 4
file_size_offset = oep_rva_offset + 4
oep_rva_bytes = decrypted_bytes[oep_rva_offset : oep_rva_offset + 4]
oep_rva = struct.unpack('<I', oep_rva_bytes)[0]
file_size_bytes = decrypted_bytes[file_size_offset : file_size_offset + 4]
file_size = struct.unpack('<I', file_size_bytes)[0]
print(f"Found OEP at: {hex(oep_rva)}")
print(f"Found second stage size: {hex(file_size)}")
second_stage_payload = decrypted_bytes[file_size_offset + 4:]

out_path = STAGE_2_PATH + "_shellcode.bin"
with open(out_path, 'wb') as f:
    f.write(second_stage_payload)

print(f"Wrote decrypted second stage shellcode to: {out_path}")
