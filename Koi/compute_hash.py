def fn_compute_hash(api_name):
    dwhash = 0x00000000

    for i in range(len(api_name)):
        dwhash = dwhash << 4
        dwhash = ord(api_name[i]) + dwhash
        a = dwhash & 0xF0000000
        if a != 0:
            x = a >> 0x18
            dwhash = dwhash ^ x & 0xFFFFFFFF
            a = (~a) & 0xFFFFFFFF
            dwhash = dwhash & a
            continue

        a = ~a
        dwhash = dwhash & a

    return dwhash

api_name = "FindResourceW"
hash_val = fn_compute_hash(api_name)
print(f"The hash value for {api_name} is {hex(hash_val)}")
# The hash value for FindResourceW is 0x5681127

api_name = "LoadResource"
hash_val = fn_compute_hash(api_name)
print(f"The hash value for {api_name} is {hex(hash_val)}")
# The hash value for LoadResource is 0x9b3b115

api_name = "SizeofResource"
hash_val = fn_compute_hash(api_name)
print(f"The hash value for {api_name} is {hex(hash_val)}")
# The hash value for SizeofResource is 0xdaa96b5