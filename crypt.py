import argparse
import string
import sys
from collections import namedtuple

Decrypted = namedtuple('Decrypted', ['vigenere', 'beaufort'])

def decrypt(ciphertext, key):
    vigenere = ""
    beaufort = ""
    key_length = len(key)
    key_as_int = [ord(i) - ord('a') for i in key]
    ciphertext_int = [ord(i) - ord('a') for i in ciphertext]
    
    for i in range(len(ciphertext_int)):
        shift = key_as_int[i % key_length]
        vig = (ciphertext_int[i] - shift) % 26
        beau =  (shift - ciphertext_int[i]) % 26
        vigenere += chr(vig + ord('a'))
        beaufort += chr(beau + ord('a'))
    
    return Decrypted(vigenere=vigenere, beaufort=beaufort)

def find_key(ciphertext, plaintext):
    vig_key = ""
    beau_key = ""
    #ciphertext = ciphertext
    #plaintext = plaintext
    
    for i in range(len(ciphertext)):
        c = ord(ciphertext[i]) - ord('a')
        p = ord(plaintext[i]) - ord('a')
        vig_key += chr((c - p) % 26 + ord('a'))
        beau_key += chr((p + c) % 26 + ord('a'))
    return Decrypted(vigenere=vig_key, beaufort=beau_key)

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-k", "--key", nargs="?", const=None)
    parser.add_argument("-c", "--cipher") # , nargs="?", const=None)
    parser.add_argument("-p", "--plain", nargs="?", const=None)
    #parser.add_argument("-l", "--length", type=int, default=0)
    #parser.add_argument("-f", "--prefix", nargs="?", type=int, const=None)
    return parser.parse_args()

def main():
    args = parse_args()
    if (args.key, args.plain) == (None, None):
        print("Either --key or --plain is required (but not both)")
    if None not in (args.key, args.plain):
        print("Specifying both --key and --plain is not allowed")

    if args.key is not None:
        decrypted = decrypt(args.cipher, args.key)
    else:
        decrypted = find_key(args.cipher, args.plain)

    print(f"(v): {decrypted.vigenere}")
    print(f"(b): {decrypted.beaufort}")

if __name__ == "__main__":
    main()
