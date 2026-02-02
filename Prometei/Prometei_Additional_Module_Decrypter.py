# Description: Prometei helper script, decrypt additional modules, remove
#              prepended NULL bytes
# Author: @YungBinary

import argparse


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
    print("Decrypt Prometei modules!")
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--file', help='The input file to decrypt.', required=True)
    parser.add_argument('-o', '--outfile', help='The output file to write plaintext.', required=True)
    parser.add_argument('-r', '--remove-nulls', help='Remove prepended NULL padding?', action="store_true", default=True)
    args = parser.parse_args()

    ciphertext = b''
    with open(args.file, 'rb') as f:
        ciphertext = f.read()

    plaintext = bytearray(len(ciphertext))

    j = 0
    for i in range(len(ciphertext)):
        j += 66
        plaintext.append(((ciphertext[i] ^ ((i*3) & 0xFF)) - j) & 0xFF)

    if args.remove_nulls:
        mz_signature = b'MZ'
        mz_position = plaintext.find(mz_signature)
        if mz_position == -1:
            raise ValueError("No MZ header found in the plaintext data!")
        plaintext = plaintext[mz_position:]

    with open(args.outfile, 'wb') as f:
        f.write(plaintext)

    print(f"Decryption finished, output file written to: {args.outfile}.")

if __name__ == "__main__":
    main()




