import base64
from urllib import parse
from itertools import cycle


def xor_data(data, key):
    return bytes(c ^ k for c, k in zip(data, cycle(key)))


def custom_b64decode(data):
    return base64.b64decode(data, altchars=b"-_", validate=True)


def decrypt_c2_request_payload(data):
    parsed_dict = parse.parse_qs(data)
    xor_key = list(parsed_dict.values())[-1]
    xor_key = xor_key[0]
    print(f"Found XOR key -> {xor_key.decode()}")

    for key, value in parsed_dict.items():
        print(f"Key: {key.decode()}")
        try:
            decoded = custom_b64decode(value[0])
            decrypted = xor_data(decoded, xor_key)
            print(f"Value: {decrypted.decode()}")
        except:
            print(f"Value: {value[0].decode()}")
            continue


def main():
    # Example of decrypting a request payload
    data=b"ykalipjjgaz=Mis1PTopJkNRTi9WT1gj&wjyfk=&ssmcpfsaiyhsyb=Ix0DBA==&nveldvverzqbhmquzg=1&jsihyjbkiqnqt=e2RrfGNsWGNsWEBrfC0JGwMJGE4gHwIDBWNsEgsVHRoJBkAPGAdrfCkJGQkKE2NsPwASExwIExpGMxYWGgEUExxrfCMPFRwJBQEAAk4zBgoHAgtGPgsHGhoOVjoJGQIVe2QrGQoPEAcHFAIDIQcIEgERBS8WBh1rfDwDEAsUEwAFE04nBR0DGwwKHwsVe2Q0IzYvO2NsIwAPGB0SFwIKVicIEAEUGw8SHwEIe2QxHwACGRkVVioDEAsIEgsUe2QxHwACGRkVVioDEAsIEgsUVi8CAA8IFQsCVjoOBAsHAk42BAESEw0SHwEIe2QxHwACGRkVViMHHwJrfDkPGAoJAR1GOwsCHw9GJgIHDwsUe2QxHwACGRkVViMTGhoPGwsCHw9GJgIHAggJBANrfDkPGAoJAR1GODprfDkPGAoJAR1GJgYJAgFGIAcDAQsUe2QxHwACGRkVVj4JBBoHFAIDVioDAAcFEx1rfDkPGAoJAR1GJQsFAxwPAhdrfDkPGAoJAR1GJQcCEwwHBGNsIQcIEgERBS8WBh1rfDkPGAoJAR02GRkDBD0OEwIKe2RrfGNsWGNsWEBrfC8WBgIPFQ8SHwEIVioHAg9rfC0JGwMVe2QlGQAIEw0SEwoiExgPFQsVJgIHAggJBANrfCpVMj0lFw0OE2NsMQEJEQIDe2QuHx0SGRwfe2QvFQEINQ8FHgtIEgxrfCMPFRwJBQEAAmNsOQADMhwPAAtrfD4HFQUHEQsVe2Q2EwsUMgcVAjwDBhsEe2Q2Gg8FEwYJGgoDBDoPGgsqGQkJMAEKEgsUe2Q2BAEBBA8LBWNsJhsEGgcVHgsUBWNsIgsLBmNsIgsLBgEUFxwfVicIAgsUGAsSVigPGgsVe2QwHxwSAw8KJRoJBAtrfGNse2RIe2RIWGNsMQEJEQIDVi0OBAELE0AKGAVrfCMPFRwJBQEAAk4jEgkDWAIIHWNse2RrfA==&vloxroxujwhh=PwgvDj0SPwo=&bskbwbszepzmoqlj=vnf"
    decrypt_c2_request_payload(data)


if __name__ == "__main__":
    main()
