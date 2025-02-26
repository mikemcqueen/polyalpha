from codec import decode_with_key, find_key
from wordgen import generate_words_with_prefix
from util import aggregate_len, safe_len

def generate_ciphers(plaintext, key_pfx, cipher_pfx, wordlist, fragments):
    """
    Generate all valid combinations of ciphertext that decode to plaintext.
    
    Args:
        plaintext (str): The target plaintext string
        wordlist (list): Sorted list of words
        key_pfx (str): Known prefix of the correct key
        cipher_pfx (str): Starting partial ciphertext
        fragments (list): List of ciphertext fragments to combine
        
    Yields:
        str: Valid ciphertext combinations that decode to plaintext
    """
    """
    if len(key_pfx) != len(cipher_pfx):
        print(f"*** len({key_pfx}) ({len(key_pfx)}) != len({cipher_pfx}) ({len(cipher_pfx)})")
        #exit()
    """
    # because, uh, not sure why exactly.
    #assert len(key_pfx) <= len(cipher_pfx)

    # Filter potential keys to only those starting with the partial key
    #valid_keys = [key for key in potential_keys if key.startswith(key_pfx)]
    
    min_length = len(plaintext)
    used_fragments = set()
    
    def backtrack(cipher, remaining_fragments, used_frags, used):
        # If current ciphertext is long enough, check if it decodes correctly with any valid key
        if len(cipher) >= min_length:
            #print(f"cipher: {cipher}")
            for key in generate_words_with_prefix(wordlist, key_pfx):
                decoded = decode_with_key(cipher, key)
                #print(f" key: {key}, decoded: {decoded}")
                if decoded.startswith(plaintext):
                    yield cipher, cipher[len(plaintext):], decoded[len(plaintext):], used_frags
                    break  # Found a valid combination, no need to try other keys
            return
        
        # Try adding each remaining fragment
        for i, fragment in enumerate(remaining_fragments):
            if tuple(used + [i]) not in used_fragments:  # Avoid duplicate combinations
                # Add this fragment and recurse
                new_remaining = remaining_fragments[:i] + remaining_fragments[i+1:]
                new_used_frags = used_frags + [fragment]
                new_used = used + [i]
                used_fragments.add(tuple(new_used))
                
                # Recursive call with yield from to bubble up yielded values
                yield from backtrack(cipher + fragment, new_remaining, new_used_frags, new_used)
    
    # Start backtracking with the partial ciphertext
    yield from backtrack(cipher_pfx, fragments, [], [])


def main():
    fragments = ['qvu', 'bma', 'aps', 'e', 'tn', 'nc', 'sc', 'ngqzp']
    wordlist = [ "balls", "boobs", "bonfire", "bucket", "fire" ]
    wordlist.sort()

    plain = "epicsno"
    key_pfx = "bonfi"
    cipher_pfx = "xzfdq"
    print(f"pln: {plain}, key_pfx: {key_pfx}, cph_pfx: {cipher_pfx}")
    for c, cs, pp, f in generate_ciphers(plain, key_pfx, cipher_pfx, wordlist, fragments):
        key = find_key(c, plain + pp)
        print(f"cph: {c}, cph_sfx: {cs}, pln_pfx: {pp}, frags: {f}, key: {key}")

    plain = "epicsno"
    key_words = ["bon"]
    key_pfx = "fi"
    cipher = "xzfdq"
    key_words_len = aggregate_len(key_words)
    
    new_plain = plain[key_words_len:]
    new_cipher = cipher[-len(key_pfx):]
    print(f"plain: {new_plain}, kp: {key_pfx}, cp: {new_cipher}")
    for c, cs, pp, f in generate_ciphers(new_plain, key_pfx, new_cipher, wordlist, fragments):
        key = find_key(c, new_plain + pp)
        print(f"cph: {c}, cph_sfx: {cs}, pln_pfx: {pp}, frags: {f}, key: {key}")


if __name__ == "__main__":
    main()
