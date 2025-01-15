import ctypes
import struct
import math

"""

Use the following command to get the volume serial via PowerShell:

(Get-WmiObject Win32_LogicalDisk | Select-Object VolumeSerialNumber).VolumeSerialNumber

"""

VOLUME_SERIAL = "8C119B2C"
HWID = "F0BC39939D003283896264"

class StealcHwidHelper():

    def __hash_dword(self, val):
        return ctypes.c_uint32((val * 0x14A30B) - 0x69427551).value

    def __hash_word(self, val):
        return ctypes.c_uint16((val * 0x14A30B) - 0x69427551).value

    def __hash_byte(self, val):
        return ctypes.c_uint8((val * 0x14A30B) - 0x69427551).value

    def make_hwid(self, volume_serial):
        part_1 = self.__hash_dword(int(volume_serial, 16))
        part_2 = self.__hash_word(part_1)

        part_3 = part_1
        barray = bytearray()
        for i in range(8):
            part_3 = self.__hash_byte(part_3)
            if i > 3:
                barray.append(part_3)

        part_3 = int.from_bytes(barray, byteorder='little')
        part_3 = str(part_3)

        hwid = f'{part_1:x}{part_2:x}{part_3}'

        return hwid.upper()

    def __modular_inverse(self, a, m):
        # Extended Euclidean Algorithm to find modular inverse
        m0, x0, x1 = m, 0, 1
        if m == 1:
            return 0
        while a > 1:
            quotient = a // m
            m, a = a % m, m
            x0, x1 = x1 - quotient * x0, x0
        if x1 < 0:
            x1 += m0
        return x1
    
    def __inverse_hash_dword(self, val):
        # Calculate the modular inverse of 0x14A30B mod 2**32
        multiplier_inverse = self.__modular_inverse(0x14A30B, 2**32)
        # Calculate val using modular arithmetic
        val = (val + 0x69427551) * multiplier_inverse % 2**32
        
        return f'{val:x}'.upper()

    def get_serial(self, hwid):
        serial = int(hwid[:8], 16)
        return self.__inverse_hash_dword(serial)

def main():
    stealc_helper = StealcHwidHelper()

    # Get the HWID given a volume serial
    hwid = stealc_helper.make_hwid(VOLUME_SERIAL)

    # Get the serial for a given HWID
    volume_serial_number = stealc_helper.get_serial(HWID)

    print(f"Volume Serial Number: {VOLUME_SERIAL}")
    print(f"Stealc HWID: {hwid}")
    print(f"Extracted Volume Serial Number {volume_serial_number} from HWID {HWID}")

if __name__ == "__main__":
    main()
