import struct
import hashlib
import uuid
import os
import base64
import string
import random
import requests
import time
import logging
from itertools import cycle
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization
from faker import Faker


logger = logging.getLogger(__name__)
logging.basicConfig(level = logging.INFO)

# Specify the C2 URL you find in the malware here
C2_URL = "http://1.1.1.1/pilot.php"
# Specify the user agent you find in the malware here
USER_AGENT = "Mozilla/5.0 (Windows NT 6.2; WOW64; Trident/7.0; rv:11.0) like Gecko"
# Specify the build id you find in the malware here
BUILD_ID = "45LkAGkF"
# Specify the threat actor(s) public key you find in the malware here (32 bytes)
# For example, the sample with MD5 "3c5d5cd7b5e48090591184ef497a98b0" has the public key located at offset 0x8C00
THREAT_ACTOR_PUBLIC_KEY = b'\x3b\xe9\x1a\xaa\x73\x7c\xeb\x59\x80\x93\x23\x39\x25\x13\xa9\xda\x18\x7f\x81\xe2\x92\x83\xd1\xfb\xc0\x07\x78\x98\x7c\x53\x41\x77'

# (Optional) Specify proxy here in the format:
# http://USERNAME:PASSWORD@PROXY_IP:PROXY_PORT
# https://USERNAME:PASSWORD@PROXY_IP:PROXY_PORT
PROXY_HTTP = ""
PROXY_HTTPS = ""

# (Optional) Specify fake domain name here
DOMAIN = ""


class KoiLoaderC2():
    def __init__(self, c2_url, user_agent, build_id, ta_public_key, domain=None, proxy_http=None, proxy_https=None):
        self._c2_url = c2_url
        self._public_key = None
        self._shared_secret = None
        self._user_agent = user_agent
        self._build_id = build_id
        self._private_key = self._generate_private_key()
        self._generate_shared_secret(ta_public_key)
        # Generate the second part of the key material (random 16 byte string)
        self._key_material_part_2 = self._generate_key_material_part_2()
        # Generate the full key material based on shared secret + random 16 byte string
        self._key_material = self._generate_key_material(self._key_material_part_2)
        # Generate the XOR key used in encrypting data to C2
        self._xor_key = self._generate_xor_key()
        # Set domain name
        self._fake_domain = domain.upper()
        # Generate fake username
        self._fake_username = self._generate_fake_username()
        # Generate fake computer name
        self._fake_computer_name = self._generate_fake_computer_name()
        # Generate a fake GUID to send to the threat actors
        self._fake_guid = str(uuid.uuid4())
        # Set proxies if provided
        self._proxies = self._configure_proxies(proxy_http, proxy_https)

    def _configure_proxies(self, proxy_http, proxy_https):
        if (proxy_http is None) != (proxy_https is None):
            raise ValueError("Both proxy_http and proxy_https must be provided")

        return { "http": proxy_http, "https": proxy_https }

    def check_in(self):
        """
        Send initial check in request, transmitting the GUID, Build ID, and Base64 encoded public key
        Returns: response object
        """

        headers = {
            "Content-Type": "application/octet-stream",
            "User-Agent": self._user_agent,
            "Proxy-Connection": "Keep-Alive",
            "Pragma": "no-cache",
            "Content-Encoding": "binary"
        }

        post_data = f"101|{self._fake_guid}|{self._build_id}|".encode()
        public_key_encoded = base64.b64encode(self._public_key)
        post_data += public_key_encoded

        #print(f"Sending check in request with post data: {post_data}, proxies: {self._proxies}")
        response = requests.post(self._c2_url, headers=headers, data=post_data, proxies=self._proxies)
        response.raise_for_status()
        return response
    
    def check_in_2(self):
        """
        Send the next check in request, transmitting the XOR key part and encrypted OS/Username/Computer Name
        Returns: response object
        """

        headers = {
            "Content-Type": "application/octet-stream",
            "User-Agent": self._user_agent,
            "Connection": "Keep-Alive",
            "Pragma": "no-cache",
            "Content-Encoding": "binary"
        }

        os_info = "10.0 (19045)"
        encrypted_data = self._xor_data(f"|{os_info}|{self._fake_username}|{self._fake_computer_name}|{self._fake_domain}".encode(), self._xor_key)
        post_data = f"111|{self._fake_guid}|{self._key_material_part_2.decode()}|".encode()
        post_data += encrypted_data

        logger.info(f"Sending check in #2 request with post data: {post_data}, proxies: {self._proxies}")
        response = requests.post(self._c2_url, headers=headers, data=post_data, proxies=self._proxies)
        response.raise_for_status()
        return response

    def get_command(self):
        """
        Send the request to the C2 to get the command
        Returns: response object
        """

        headers = {
            "Content-Type": "application/octet-stream",
            "User-Agent": self._user_agent,
            "Proxy-Connection": "Keep-Alive",
            "Pragma": "no-cache",
            "Content-Encoding": "binary"
        }

        post_data = f"102|{self._fake_guid}".encode()

        logger.info(f"Sending get commands request with post data: {post_data}, proxies: {self._proxies}")
        response = requests.post(self._c2_url, headers=headers, data=post_data, proxies=self._proxies)
        response.raise_for_status()
        return response

    def _generate_xor_key(self):
        # MD5 hash the key material, creating the XOR key
        md5 = hashlib.md5()
        md5.update(self._key_material)
        return md5.digest()

    def _generate_private_key(self):
        secret = bytearray(os.urandom(32))
        secret[0] &= 0xF8
        return bytes(secret)

    def _generate_shared_secret(self, ta_public_key):
        """
        Generate and set the public key and shared secret, given the threat actor public key.

        ta_public_key: bytes object representing the threat actor public key
        """

        # Generate private key
        secret_key_bytes = self._private_key

        # Create X25519PrivateKey object
        private_key = x25519.X25519PrivateKey.from_private_bytes(secret_key_bytes)

        # Generate the corresponding public key
        public_key = private_key.public_key()

        # Get the public key as raw bytes
        public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

        # Print the public key in hexadecimal format
        logger.info(f"Generated public Key: {public_key_bytes.hex()}")

        loaded_public_key = x25519.X25519PublicKey.from_public_bytes(THREAT_ACTOR_PUBLIC_KEY)

        # Perform the X25519 key exchange, taking the generated private key and
        # the malware devs public key
        shared_secret_bytes = private_key.exchange(loaded_public_key)

        # Print computed shared secret
        logger.info(f"Computed shared secret: {shared_secret_bytes.hex()}")
        self._public_key = public_key_bytes
        self._shared_secret = shared_secret_bytes

    def _generate_key_material_part_2(self):
        """
        Simulate KoiLoader's generation of a random string.
        This is used as the second part of the key material.
        """
        return ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(16)).encode()

    def _generate_key_material(self, part_2):
        xor_key = self._shared_secret + part_2
        return xor_key

    def _xor_data(self, data, key):
        return bytes(c ^ k for c, k in zip(data, cycle(key)))

    def _generate_fake_computer_name(self):
        computer_name = "DESKTOP-" + ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(7))
        logger.info(f"Generated fake computer name: {computer_name}")
        return computer_name

    def _generate_fake_username(self):
        fake = Faker()
        username = fake.first_name().lower() + "." + fake.last_name().lower()
        logger.info(f"Generated fake username: {username}")
        return username


def main():

    # Instantiate KoiLoaderC2 class
    koiloader_c2 = KoiLoaderC2(
        C2_URL, USER_AGENT,
        BUILD_ID,
        THREAT_ACTOR_PUBLIC_KEY,
        DOMAIN,
        PROXY_HTTP,
        PROXY_HTTPS
    )

    # Send initial check in request, transmitting the GUID, Build ID, and Base64 encoded public key
    response = koiloader_c2.check_in()
    logger.info(f"Check in status code: {response.status_code}")

    # Send next check in request, transmitting the encrypted OS info, username, and computer name
    response = koiloader_c2.check_in_2()
    logger.info(f"Check in #2 status code: {response.status_code}")
    
    # Send request to get command from the C2
    while True:
        response = koiloader_c2.get_command()
        logger.info(f"Get commands response status code: {response.status_code}")
        if response.text:
            logger.info(f"Received command from C2: {response.text}")

        # Sleep for 1 second before retrying
        time.sleep(1)

if __name__ == "__main__":
    main()
