import argparse
import string
import sys
from collections import namedtuple
Decrypted = namedtuple('Decrypted', ['vigenere', 'beaufort'])

def clean_text(text):
    """Remove punctuation and convert to lowercase."""
    text = text.lower()
    text = text.translate(str.maketrans('', '', string.punctuation))
    return text

def beaufort_decrypt(ciphertext, key):
    """Decrypt Beaufort cipher with given key."""
    plaintext = ""
    key_length = len(key)
    key_as_int = [ord(i) - ord('a') for i in key]
    ciphertext_int = [ord(i) - ord('a') for i in ciphertext]
    
    for i in range(len(ciphertext_int)):
        # Key difference: Beaufort uses (key - ciphertext) mod 26
        # instead of Vigenère's (ciphertext - key) mod 26
        plain = (key_as_int[i % key_length] - ciphertext_int[i]) % 26
        plaintext += chr(plain + ord('a'))
    
    return plaintext

def vigenere_decrypt(ciphertext, key):
    """Decrypt Vigenère cipher with given key."""
    plaintext = ""
    key_length = len(key)
    key_as_int = [ord(i) - ord('a') for i in key]
    ciphertext_int = [ord(i) - ord('a') for i in ciphertext]
    
    for i in range(len(ciphertext_int)):
        shift = key_as_int[i % key_length]
        plain = (ciphertext_int[i] - shift) % 26
        plaintext += chr(plain + ord('a'))
    
    return plaintext

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

def load_words_to_set(filename):
    # Load words from file into a set for O(1) lookup.
    word_set = set()
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            for line in f:
                word = clean_text(line.strip())
                if word:  # Only add non-empty words
                    word_set.add(word)
        #print(f"Loaded {len(word_set)} words into set")
        return word_set
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found")
        return set()

def add_solution(solutions, key, word, value):
    if not key in solutions:
        solutions[key] = [(word, value)];
    else:
        solutions[key].append((word, value));

def add_prefix_solution(solutions, plain, key, word, wordset, args):
    if args.plain_prefix is not None and not plain.startswith(args.plain_prefix):
        return
    if args.key_prefix is not None and not key.startswith(args.key_prefix):
        return
    plain_prefix = plain[args.plain_offset:args.plain_offset + args.length]
    for word in wordset:
        if word.startswith(plain_prefix):
            add_solution(solutions, key, word, plain_prefix)

def add_any_prefix_solutions(solutions, decrypted, key, word, wordset, args):
#    add_prefix_solution(solutions, decrypted.vigenere, key, word, wordset, args)
    add_prefix_solution(solutions, decrypted.beaufort, key, word, wordset, args)

def find_solutions(ciphertext, wordset, args, found_keys):
    solutions = {}
    clean_cipher = clean_text(ciphertext)
    
    # Iterate through wordset for keys
    for word in wordset:
        if len(word) < args.length:
            continue
        if args.key_prefix is not None:
            word = args.key_prefix + word
        key = word[:args.length]
        #if key == "ti":
        #    print(f"***{key}***")
        #if key in found_keys:
        #    continue
        #found_keys.add(key_prefix)
        decrypted = decrypt(clean_cipher, key)
        if (args.key_prefix, args.plain_prefix) == (None, None):
            #if decrypted.vigenere[:args.length] in wordset:
            #    add_solution(solutions, key, word, decrypted.vigenere[:len(word)])
            if decrypted.beaufort[:args.length] in wordset:
                add_solution(solutions, key, word, decrypted.beaufort[:len(word)])
        else:
            add_any_prefix_solutions(solutions, decrypted, key, word, wordset, args)
       
    return solutions

def show_solutions(solutions, args):
    if not solutions:
        print("No solutions found.")
        return
    
    #print(f"\nFound {len(solutions)} solutions:")
    shown_values = set()
    for key, values in solutions.items():
        if args.verbose:
            print(f"Key: {key}")
            for v in values:
                if v[0] not in shown_values:
                    print(f"  {v[0]:<20} {v[1]}")
                    shown_values.add(v[0])
        else:
            print(f"Key: {key:<20} {values[0][1]}")

def parse_args():
    parser = argparse.ArgumentParser()
    #parser.add_argument("-k", "--key", nargs="?", const=None)
    #parser.add_argument("-p", "--plain", nargs="?", const=None)
    parser.add_argument("--pp", nargs="?", type=str, const=None, help="--plain-prefix")
    parser.add_argument("--uc", help="--used-cipher")
    #parser.add_argument("-l", "--length", type=int, default=0)
    parser.add_argument("-d", "--dict", default="/usr/share/dict/words")
    parser.add_argument('-v', '--verbose', action='store_true')
    return parser.parse_args()

def main():
    #ciphertext = "QVUEBMAXZFDQAPSNGQZP"
    #ciphertext = "XZFDQNGQZP"
    #ciphertext = "XZFDQAPSNGQZP"
    args = parse_args()
    #if (args.key, args.plain) == (None, None):
    #    print("Either --key or --plain must be specified")
    #    return
    if not args.length:
        print("--length is required")
        return

    #print(f"ciphertext: {args.cipher}")
    # Load words into set for O(1) lookup
    wordset = load_words_to_set(args.dict)
    if not wordset:
        print("Error: Empty dictionary")
        return
        
    # Find solutions using set for both key source and word validation
    solutions = find_solutions(args.cipher, wordset, args, set())
    show_solutions(solutions, args)

if __name__ == "__main__":
    #decrypted = decrypt("jeeno", "cat")
    #print(decrypted.vigenere)
    main()
