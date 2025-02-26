
def find_key(cipher, plain):
    #vig_key = ""
    beau_key = ""
    min_len = min(len(cipher), len(plain))
    for i in range(min_len):
        c = ord(cipher[i]) - ord('a')
        p = ord(plain[i]) - ord('a')
        #vig_key += chr((c - p) % 26 + ord('a'))
        beau_key += chr((p + c) % 26 + ord('a'))
    return beau_key


def beaufort_decrypt(cipher, key):
    plain = ""
    key_length = len(key)
    key_as_int = [ord(i) - ord('a') for i in key]
    cipher_as_int = [ord(i) - ord('a') for i in cipher]
    for i in range(len(cipher_as_int)):
        plain_as_int = (key_as_int[i % key_length] - cipher_as_int[i]) % 26
        plain += chr(plain_as_int + ord('a'))
    return plain
    

def decode_with_key(cipher, key):
    return beaufort_decrypt(cipher, key)


