import string
import sys

def clean_text(text):
    """Remove punctuation and convert to lowercase."""
    text = text.lower()
    text = text.translate(str.maketrans('', '', string.punctuation))
    return text

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

def load_words_to_set(filename):
    """
    Load words from file into a set for O(1) lookup.
    Returns a set of cleaned words.
    """
    word_set = set()
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            for line in f:
                word = clean_text(line.strip())
                if word:  # Only add non-empty words
                    word_set.add(word)
        print(f"Loaded {len(word_set)} words into set")
        return word_set
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found")
        return set()

def find_solutions(ciphertext, wordset, found_keys):
    """
    Use each word in wordset as potential key.
    Check if decryption is in wordset (O(1) lookup).
    """
    solutions = []
    clean_cipher = clean_text(ciphertext)
    
    # Iterate through wordset for keys
    for key in wordset:
        key = key[:len(clean_cipher)]
        if key in found_keys:
            continue
        found_keys.add(key)
        decrypted = vigenere_decrypt(clean_cipher, key)
        #print(decrypted)
        # O(1) lookup in wordset
        if decrypted in wordset:
            solutions.append({
                'key': key,
                'plaintext': decrypted
            })
       
    return solutions

def main():
    dict_file = "/usr/share/dict/words"
    if len(sys.argv) < 2:
        ciphertext = "qvu"
    else:
        ciphertext = sys.argv[1]
    
    print(f"ciphertext: {ciphertext}")
    # Load words into set for O(1) lookup
    wordset = load_words_to_set(dict_file)
    if not wordset:
        print("Error: Empty dictionary")
        return
        
    # Find solutions using set for both key source and word validation
    solutions = find_solutions(ciphertext, wordset, set())
    
    # Print results
    if solutions:
        print(f"\nFound {len(solutions)} solutions:")
        for solution in solutions:
            print(f"Key: {solution['key']}")
            print(f"Plaintext: {solution['plaintext']}")
            print("---")
    else:
        print("\nNo solutions found.")

if __name__ == "__main__":
    decrypted = vigenere_decrypt("jeeno", "cat")
    print(decrypted)
    main()
