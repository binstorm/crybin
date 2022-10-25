def encrypt(data, key):
    return bytearray([data[i] ^ key for i in range(len(data))])

def generate_unpacker(key):
    pass
