import argparse
from itertools import permutations, tee
import base64

class TextDecoder:
    def __init__(self, fragments, wordlist_path, min_word_length=1):
        self.fragments = fragments
        self.target_length = sum(len(f) for f in fragments)
        self.min_word_length = min_word_length
        self.wordlist = self._load_wordlist(wordlist_path)
        
    def _load_wordlist(self, path):
        with open(path, 'r') as f:
            return set(
                word.strip().lower() 
                for word in f 
                if len(word.strip()) >= self.min_word_length
            )

    def create_key_generator(self, target_length):
        """
        Factory function that returns a new generator for word combinations
        
        Args:
            target_length (int): Desired total length of combined words
            
        Returns:
            generator: Yields word combinations that sum to target length
        """
        def generate_combinations(current_words=None, current_length=0):
            if current_words is None:
                current_words = []
                
            if current_length == target_length:
                yield current_words
                return
                
            if current_length > target_length:
                return
                
            remaining_length = target_length - current_length
            if remaining_length < self.min_word_length:
                return
                
            for word in self.wordlist:
                if len(word) <= remaining_length:
                    yield from generate_combinations(
                        current_words + [word],
                        current_length + len(word)
                    )
                    
        return generate_combinations()

    def process_fragment_permutation(self, fragment_perm, key_gen):
        """
        Process a fragment permutation with all keys from a generator
        
        Args:
            fragment_perm: Current fragment permutation
            key_gen: Generator for possible keys
            
        Yields:
            tuple: (fragment_perm, key_words, decoded_text, valid_words)
        """
        encoded_text = ''.join(fragment_perm)
        
        # Iterate through all keys from the generator
        num_keys = 0
        for key_words in key_gen:
            key = ''.join(key_words)
            num_keys += 1
            if num_keys % 100 == 0:
                print(f"\r keys: {num_keys}", end="", flush=True)
            # Try decoding with current key
            decoded = self.decode_with_key(encoded_text, key)
            if decoded:
                valid_words = self.verify_decoded_text(decoded)
                if valid_words:
                    yield (fragment_perm, key_words, decoded, valid_words)

    def beaufort_decrypt(self, ciphertext, key):
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

    def decode_with_key(self, encoded_text, key):
        return self.beaufort_decrypt(encoded_text, key)

    def verify_decoded_text(self, text):
        """Find valid word combinations that match decoded text exactly"""
        if len(text) != self.target_length:
            return []
            
        def find_exact_matches(remaining_text, current_words=None):
            if current_words is None:
                current_words = []
                
            if not remaining_text:
                return [current_words]
                
            if len(remaining_text) < self.min_word_length:
                return []
                
            results = []
            for word in self.wordlist:
                if remaining_text.startswith(word):
                    new_results = find_exact_matches(
                        remaining_text[len(word):],
                        current_words + [word]
                    )
                    results.extend(new_results)
                    
            return results
            
        return find_exact_matches(text.lower())

    def process_all(self):
        for frag_perm in permutations(self.fragments):
            print(f"frags: {''.join(frag_perm)}")
            key_gen = self.create_key_generator(self.target_length)
            yield from self.process_fragment_permutation(frag_perm, key_gen)

# Example usage:
"""
fragments = ['SGV', 'sbG8', 'gd29y', 'bGQ=']
decoder = TextDecoder(fragments, 'path/to/wordlist.txt', min_word_length=3)

for frag_perm, key_words, decoded, valid_words in decoder.process_all():
    print(f"\nFragment permutation: {' '.join(frag_perm)}")
    print(f"Key words: {' '.join(key_words)}")
    print(f"Decoded text: {decoded}")
    print("Valid word combinations:")
    for words in valid_words:
        print(f"  {' '.join(words)}")
"""
def parse_args():
    parser = argparse.ArgumentParser()
    #parser.add_argument("-k", "--key", nargs="?", const=None)
    #parser.add_argument("-e", "--key-prefix", nargs="?", type=str, const=None)
    #parser.add_argument('-y', '--key-offset', type=int, default=0)
    #parser.add_argument("-p", "--plain", nargs="?", const=None)
    #parser.add_argument("-a", "--plain-prefix", nargs="?", type=str, const=None)
    #parser.add_argument('-i', '--plain-offset', type=int, default=3)
    #parser.add_argument("-c", "--cipher", default="XZFDQNGQZP")
    parser.add_argument("-m", "--min_word_length", type=int, default=3)
    parser.add_argument("-d", "--dict", default="/usr/share/dict/words")
    #parser.add_argument('-v', '--verbose', action='store_true')
    return parser.parse_args()
        
# Example usage:
args = parse_args()
fragments = ['QVU', 'BMA', 'APS', 'E']
#word_list_filename = '/usr/local/share/dict'
decoder = TextDecoder(fragments, args.dict, min_word_length=3)

for frag_perm, key_words, decoded, valid_words in decoder.process_all():
    print(f"\nFragment permutation: {' '.join(frag_perm)}")
    print(f"Key words: {' '.join(key_words)}")
    print(f"Decoded text: {decoded}")
    print("Valid word combinations:")
    for words in valid_words:
        print(f"  {' '.join(words)}")

