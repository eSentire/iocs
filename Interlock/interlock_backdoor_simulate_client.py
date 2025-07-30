"""
Author: YungBinary
Description: Simulate C2 interaction with C-based Interlock Backdoor
"""


import socket
import json
import time
import os
import random
import struct

# The seed is based on _time64()
RNDSEED = int(time.time())

def rand():
    global RNDSEED
    RNDSEED = (RNDSEED * 214013 + 2531011) & 0xffffffff
    return (RNDSEED >> 16) & 0x7fff


def xor_generate(last_result: int):
    word1 = rand()
    word2 = rand()
    packed = struct.pack('<HH', word1, word2)
    a1 = word1 & 0xFF
    a2 = (a1 * 2) & 0xFF
    a3 = ((last_result ^ a2) ^ a1) & 0xFF

    return packed, a3


class TCPClient:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.socket = None
    
    def connect(self):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))
            print(f"Connected to C2: {self.host}:{self.port}")
        except Exception as e:
            print(f"Error connecting: {str(e)}")
            self.close()

    def send_data(self, data):
        try:
            sent = 0
            while sent < len(data):
                self.socket.settimeout(300)
                bytes_sent = self.socket.send(data[sent:])
                if bytes_sent == 0:
                    raise RuntimeError("Socket connection broken")
                sent += bytes_sent
            return sent
        except Exception as e:
            raise Exception(f"Error sending data: {str(e)}")

    def receive_data(self, bytes_to_receive):
        try:
            data = bytearray()
            while len(data) < bytes_to_receive:
                packet = self.socket.recv(bytes_to_receive - len(data))
                if not packet:
                    raise RuntimeError("Socket connection broken")
                data.extend(packet)
            return bytes(data)
        except Exception as e:
            raise Exception(f"Error receiving data: {str(e)}")

    def xor_data(self, data, key):
        """XOR the data with the given key"""
        return bytes([b ^ key for b in data])
    
    def xor_interlock(self, pCipherText_bytes: bytes, dwCipherTextLen: int, dwXorKey: int) -> bytearray:
        """
        Decrypts a C2 response using a specific XOR-based algorithm.
        """
        
        # Create a bytearray from the input bytes
        pCipherText = bytearray(pCipherText_bytes)
        v4 = dwXorKey
        v4_bytes = v4.to_bytes(4, 'little') 

        if dwCipherTextLen:
            for i in range(dwCipherTextLen):
                dwXorKey = i + 2 * dwXorKey
                pCipherText[i] ^= v4_bytes[i & 3] ^ (dwXorKey & 0xFF)
                
        return pCipherText

    def close(self):
        try:
            if self.socket:
                self.socket.close()
                print("Connection closed")
        except Exception as e:
            print(f"Error closing connection: {str(e)}")


def main():
    # Connect to the C2
    c2_server = 'REPLACEME'
    client = TCPClient(c2_server, 443)
    client.connect()
    
    # Send initial callback
    magic = b"\x55\x11\x69\xDF"
    data = {
        "iptarget": c2_server,
        "domain": "REPLACEME",
        "pcname": "REPLACEME",
        "username": "REPLACEME",
        "runas": 1, # Integrity level medium
        "typef": 2, # Hard-coded
        "veros": 15 # 15 = Windows 11, 11 = Windows 10
    }
    json_data = json.dumps(data).encode('utf-8')
    initial_callback = magic + json_data
    client.send_data(initial_callback)
    # Check if the C2 rejected the initial callback
    # If it returns 1, the backdoor deletes itself
    # If it returns 2, the backdoor exits
    c2_response = client.receive_data(bytes_to_receive=1)
    
    if c2_response == 1:
        print("C2 wants the client to delete itself and exit.")
    elif c2_response == 2:
        print("C2 wants the client to exit.")
    else:
        print("C2 accepted the initial callack.")
    
    
    last_result = 0x02
    while True:

        # Poll for command data
        print("Checking for commands...")
        received_data = client.receive_data(bytes_to_receive=12)
        
        # XOR the received data with 0x4D
        print(f"Encoded Command Received (hex): {received_data.hex()}")
        xored_data = client.xor_data(received_data, 0x4D)
        print(f"Command Data After XOR with 0x4D (hex): {xored_data.hex()}")

        # Parse the command, xor key, and size of the encrypted data
        # to recieve from the response
        command = xored_data[0]
        xor_key = xored_data[-4:]
        size_encrypted = int.from_bytes(xored_data[4:7], byteorder="little")
        print(f"Command received: {command}")
        print(f"XOR key received (hex): {xor_key.hex()}")
        print(f"Encrypted data size: {size_encrypted}")
        

        # Decrypt the encrypted data
        received_data = client.receive_data(bytes_to_receive=size_encrypted)
        if command != 1:
            print(f"Received data (hex): {received_data.hex()}")
            decrypted_data = client.xor_interlock(received_data, size_encrypted, int.from_bytes(xor_key, byteorder="little"))
            print(f"Decrypted data: {decrypted_data.hex()}")
        
        # TODO handle additional commands and associated decrypted data
        if command == 0:
            print(f"Command: 0 (The server suspects something went wrong with last sent data)")
        elif command == 1:
            print(f"Command: 1 (Wait for further commands)")
        elif command == 4 or command == 5:
            print(f"Command: {command} (Delete Self)")
        elif command == 6:
            print("Command: 6 (Update C2 servers to disk)")
            c2_servers = [decrypted_data[i:i+4] for i in range(0, len(decrypted_data), 4)]
            c2_servers = [socket.inet_ntoa(i) for i in c2_servers]
            print(f"    {c2_servers}")


        sleep_random_seconds = (rand() % 30000 + 60000) / 1000
        print(f"Sleeping for {sleep_random_seconds} seconds")
        time.sleep(sleep_random_seconds)

        # Send heartbeat data and continue checking for commands
        packed, result = xor_generate(last_result)
        last_result = result
        heartbeat = b'\x01\x00\xff\xff\x01\x00\x00\x00' + packed
        encrypted_heartbeat = client.xor_data(heartbeat, 0x4D)

        print(f"Sending heartbeat: {encrypted_heartbeat.hex()}")
        client.send_data(encrypted_heartbeat)
        print(f"Sending heartbeat verification byte: {hex(last_result)}")
        client.send_data(last_result.to_bytes(1, 'big'))
    
    client.close()

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
    print("Probe Interlock C2 infrastructure.")
    main()
