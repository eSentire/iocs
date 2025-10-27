"""
Description: Unpacks NetSupport PowerShell based loaders
Author: YungBinary
SHA256 of samples:
    1ecd721749ed2c6c36b1dea9a99eae3cb5b8ec56f7fa43d0310a1d087f5cee00 - Base64 encoded, dropped file names are random
    6b4219acaa29bb1b028a57c291dec2505d48ff75dbc308bfdb5b995cb255fefb - Base64 encoded
    40b44114c57619056d628d4c6290b7eb081d89332dbf9728384aa5feac4b4c7a - Byte arrays
    a823031ba57d0e5f7ef15d63fe93a05ed00eadfd19afc7d2fed60f20e651a8bb - Base64 -> JSON
    2bd3a8ebf7e059e776bf9ed1a87f455467087e8e845618795e7dec6318d2ccad - Base64 -> JSON (older variant)
"""

import json
import os
import sys
import base64
import hashlib
import re
import uuid
from io import BytesIO
import zipfile


def process_code_blocks(text):
    """Process multiple file blocks"""

    results = {"paths": [], "data": []}

    split_pattern = r'\$\w+\s*=\s*Join-Path\s+\$\w+\s+([\'"])(.+?)\1;?'
    base64_pattern = r'\$\w+\s*\+=\s*[\'"](.+?)[\'"]'
    
    parts = re.split(split_pattern, text)

    for i in range(0, len(parts) - 2, 3):
        base64_block = parts[i].strip()
        filename = parts[i + 2]

        if base64_block:
            # Extract all base64 values from the block
            base64_values = re.findall(base64_pattern, base64_block)
            combined_base64 = ''.join(base64_values)

            results["paths"].append(filename)
            results["data"].append(combined_base64)

    # If file names are associated with a map, map them
    map_pattern = r'[\'"](.+?)[\'"]\s*=\s*[\'"](.+?)[\'"]'
    mappings = {}
    for match in re.finditer(map_pattern, text):
        fake_name = match.group(1)
        real_name = match.group(2)
        results["paths"] = [path.replace(fake_name, real_name) for path in results["paths"]]

    return results


def extract_zip_bytes_from_byte_arrays(text):
    """Extract all byte arrays, concatenate, and return bytes of zip"""

    # Pattern to match [byte[]]$varname = @( ... )
    pattern = r'\[byte\[\]\]\$\w+\s*=\s*@\(([\s\S]*?)\)'

    # Find all matches
    matches = re.findall(pattern, text)

    all_numbers = []

    for content in matches:
        # Extract numbers from each match
        numbers = re.findall(r'\d+', content)
        all_numbers.extend([int(n) for n in numbers])

    return bytes(all_numbers)


def extract_base64_contents(text):
    pattern = r'@\("(.*?)"\) ?-join'
    match = re.search(pattern, text, re.DOTALL)
    if match:
        return match.group(1)
    pattern2 = r'(["\'])([A-Za-z0-9+/]{1000,}={0,2})\1'
    match = re.search(pattern2, text, re.DOTALL)
    if match:
        return match.group(2)
    return None


def read_file(file_path):
    with open(file_path, "r") as f:
        return f.read()


def main():
    if not os.path.exists(sys.argv[1]) or not os.path.isfile(sys.argv[1]):
        raise ValueError(f"File path does not exist: {sys.argv[1]}")

    powershell_contents = read_file(sys.argv[1])
    if not powershell_contents:
        raise ValueError(f"Unable to read file contents for the file: {sys.argv[1]}")

    output_dir = str(uuid.uuid4())

    # Handle variants that concatenate byte arrays into a zip archive
    zip_bytes = extract_zip_bytes_from_byte_arrays(powershell_contents)
    if zip_bytes:
        with zipfile.ZipFile(BytesIO(zip_bytes), 'r') as zip_ref:
            bad_file = zip_ref.testzip()
            if not bad_file:
                os.makedirs(output_dir, exist_ok=True)
                for file_info in zip_ref.filelist:
                    if file_info.is_dir():
                        continue

                    file_content = zip_ref.read(file_info.filename)
                    sha256 = hashlib.sha256(file_content).hexdigest()
                    zip_ref.extract(file_info.filename, output_dir)
                    outpath = os.path.join(output_dir, file_info.filename)
                    print(f"Extracted: {outpath}, SHA256: {sha256}")
                print("Done.")
                return

    # Handle variants that are LLM generated, use Base64
    payloads_dict = process_code_blocks(powershell_contents)
    if "paths" in payloads_dict and "data" in payloads_dict and payloads_dict["paths"] and payloads_dict["data"]:
        filenames = payloads_dict["paths"]
        base64_payloads = payloads_dict["data"]
        os.makedirs(output_dir, exist_ok=True)
        success = True
        for i in range(len(filenames)):
            filename = filenames[i]
            base64_payload = base64_payloads[i]
            if not filename or not base64_payload:
                success = False
                break
            outpath = os.path.join(output_dir, filename)
            f = open(outpath, "wb")
            decoded_payload = base64.b64decode(base64_payload)
            f.write(decoded_payload)
            f.close()
            sha256 = hashlib.sha256(decoded_payload).hexdigest()
            print(f"Extracted: {outpath}, SHA256: {sha256}")

        if success:
            print("Done.")
            return
    
    # Handle variants that are JSON based
    base64_contents = extract_base64_contents(powershell_contents)
    if not base64_contents:
        print(f"Unsupported NetSupport loader, please contact x.com/YungBinary")
        return

    decoded_json = base64.b64decode(base64_contents)
    payloads_dict = json.loads(decoded_json.decode())

    key = next(iter(payloads_dict.keys()))
    os.makedirs(output_dir, exist_ok=True)
    if key != "paths":
        for _, payload_dict in enumerate(payloads_dict[key]):
            keys_iterator = iter(payload_dict.keys())
            filename_key = next(keys_iterator)
            base64_payload_key = next(keys_iterator)
            filename = payload_dict[filename_key]
            base64_payload = payload_dict[base64_payload_key]
            outpath = os.path.join(output_dir, filename)
            f = open(outpath, "wb")
            decoded_payload = base64.b64decode(base64_payload)
            f.write(decoded_payload)
            f.close()
            sha256 = hashlib.sha256(decoded_payload).hexdigest()
            print(f"Extracted: {outpath}, SHA256: {sha256}")
    elif "paths" in payloads_dict and "data" in payloads_dict:
        filenames = payloads_dict["paths"]
        base64_payloads = payloads_dict["data"]
        for i in range(len(filenames)):
            filename = filenames[i]
            base64_payload = base64_payloads[i]
            outpath = os.path.join(output_dir, filename)
            f = open(outpath, "wb")
            decoded_payload = base64.b64decode(base64_payload)
            f.write(decoded_payload)
            f.close()
            sha256 = hashlib.sha256(decoded_payload).hexdigest()
            print(f"Extracted: {outpath}, SHA256: {sha256}")
    else:
        print("Unsupported NetSupport loader, please contact x.com/YungBinary")


    print("Done.")


if __name__ == "__main__":
    logo = """
███████╗░██████╗███████╗███╗░░██╗████████╗██╗██████╗░███████╗
██╔════╝██╔════╝██╔════╝████╗░██║╚══██╔══╝██║██╔══██╗██╔════╝
█████╗░░╚█████╗░█████╗░░██╔██╗██║░░░██║░░░██║██████╔╝█████╗░░
██╔══╝░░░╚═══██╗██╔══╝░░██║╚████║░░░██║░░░██║██╔══██╗██╔══╝░░
███████╗██████╔╝███████╗██║░╚███║░░░██║░░░██║██║░░██║███████╗
╚══════╝╚═════╝░╚══════╝╚═╝░░╚══╝░░░╚═╝░░░╚═╝╚═╝░░╚═╝╚══════╝
"""
    print(logo)
    print("Unpack NetSupport Manager RAT PowerShell loader.")
    main()
