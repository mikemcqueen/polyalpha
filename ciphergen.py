from codec import decode_with_key, find_key
from wordgen import Words, generate_words_with_prefix, contains_words_and_word_prefix
from util import aggregate_len, safe_len, load_wordlist, parse_args, join

def old_generate_ciphers_for_key(key, plain_pfx, cipher_pfx, fragments, words, verbose=False):
    """
    Generate all valid combinations of ciphertext that when decoded with the supplied key,
    results in zero or more plaintext words, optionally followed by a valid word prefix.
    
    Args:
        key (str): the key
        cipher_pfx (str): Starting partial ciphertext
        wordlist (list): Sorted list of words
        fragments (list): List of ciphertext fragments to combine
        
    Yields:
        str: Valid ciphertext combinations that decode to plaintext words/prefix sequence.
    """
    min_length = len(key)
    used_fragments = set()
    
    def backtrack(cipher, remaining_fragments, used_frags, used):
        # If current ciphertext is long enough, check if it decodes correctly with any valid key
        if len(cipher) >= min_length:
            cipher_sfx = cipher[len(key):] or None
            cipher = cipher[:len(key)]
            plain = decode_with_key(cipher, key)
            plain = plain[safe_len(plain_pfx):]
            if contains_words_and_word_prefix(plain, words):
                yield cipher, cipher_sfx, plain, remaining_fragments
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
    
    if verbose:
        print(f"gen_ciphers_for_key(k: {key}, pp: {plain_pfx}, cp: {cipher_pfx}, f: {fragments})")
    # Start backtracking with the partial ciphertext
    yield from backtrack(cipher_pfx, fragments, [], [])

def generate_ciphers_for_key(ctx, md):
    def backtrack(fragments, used_fragments):
        if fragments:
            #cipher = ctx.cipher + join(fragments)
            cipher = ctx.cipher + join(ctx.fragments[i] for i in fragments)
            plain = decode_with_key(cipher[:len(ctx.key)], ctx.key)
            if not contains_words_and_word_prefix(plain, md.words):
                return
            
            if len(cipher) >= len(ctx.key):
                if (md.verbose): print(f"{' ' * ctx.level} gen_cfk:{ctx.level} p: {plain}, k: {ctx.key}, c: {cipher}")
                yield cipher, [frag for idx, frag in enumerate(ctx.fragments) if idx not in used_fragments]
                return
        
        for i in range(0, len(ctx.fragments)):
            if i in used_fragments:
                continue
            used_fragments.add(i)
            fragments.append(i) #ctx.fragments[i])
            yield from backtrack(fragments, used_fragments)
            fragments.pop()
            used_fragments.remove(i)
    
    yield from backtrack([], set())

def generate_ciphers_for_plaintext(ctx, md):
    min_cipher_length = aggregate_len(ctx.key_words) + 2
    if len(ctx.cipher) >= min_cipher_length:
        yield ctx.cipher, ctx.fragments

    def backtrack(fragments, used_fragments):
        if fragments:
            frags = join(ctx.fragments[i] for i in fragments)
            cipher = ctx.cipher + frags
            #if len(cipher) >= len(ctx.plaintext):
            #if len(frags) >= min_frag_length:
            if len(cipher) >= min_cipher_length:
                #if (md.verbose): print(f"{' ' * ctx.level} gen_ac:{ctx.level} p: {plain}, k: {ctx.key}, c: {cipher}")
                yield cipher + frags, [frag for idx, frag in enumerate(ctx.fragments) if idx not in used_fragments]
                return
        
        for i in range(0, len(ctx.fragments)):
            if i in used_fragments:
                continue
            used_fragments.add(i)
            fragments.append(i)
            yield from backtrack(fragments, used_fragments)
            fragments.pop()
            used_fragments.remove(i)
    
    yield from backtrack([], set())


def generate_ciphers(plaintext, key_pfx, cipher_pfx, wordlist, fragments):
    """
    Generate all valid combinations of ciphertext that decode to plaintext.
    
    Args:
        plaintext (str): The target plaintext string
        key_pfx (str): Known prefix of the correct key
        cipher_pfx (str): Starting partial ciphertext
        wordlist (list): Sorted list of words
        fragments (list): List of ciphertext fragments to combine
        
    Yields:
        str: Valid ciphertext combinations that decode to plaintext
    """
    """
    if len(key_pfx) != len(cipher_pfx):
        print(f"*** len({key_pfx}) ({len(key_pfx)}) != len({cipher_pfx}) ({len(cipher_pfx)})")
        #exit()
    """
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


"""
p epicsno, k: bonfi, c: xzfdq
c: xzfdqeqvu, c: vu, p gu, frags: ['e', 'qvu'], key: bonfirebo
"""
def test_generate_ciphers(fragments, wordlist):
    plain = "epicsno"
    key_pfx = "bonfi"
    cipher_pfx = "xzfdq"
    print(f"p {plain}, k: {key_pfx}, c: {cipher_pfx}")
    for c, cs, pp, f in generate_ciphers(plain, key_pfx, cipher_pfx, wordlist, fragments):
        key = find_key(c, plain + pp)
        print(f"c: {c}, c: {cs}, p {pp}, frags: {f}, key: {key}")


"""
plain: csno, kp: fi, cp: dq
c: dqeqvu, c: vu, p ko, frags: ['e', 'qvu'], key: firefi
"""
def test_generate_ciphers2(fragments, wordlist):
    plain = "epicsno"
    key_words = ["bon"]
    key_pfx = "fi"
    cipher = "xzfdq"
    key_words_len = aggregate_len(key_words)
    
    new_plain = plain[key_words_len:]
    new_cipher = cipher[-len(key_pfx):]
    print(f"--\nplain: {new_plain}, kp: {key_pfx}, cp: {new_cipher}")
    for c, cs, pp, f in generate_ciphers(new_plain, key_pfx, new_cipher, wordlist, fragments):
        key = find_key(c, new_plain + pp)
        print(f"c: {c}, c: {cs}, p {pp}, frags: {f}, key: {key}")


def test_generate_ciphers_for_key(fragments, words, verbose):
    plain = "epic"
    key_words = ["bon"]
    cipher = "xzfdq"
    key_words_len = aggregate_len(key_words)
    plain_pfx = plain[key_words_len:]
    cipher_pfx = cipher[key_words_len:]

    key = "fire"
    print(f"--\nk: {key}, cp: {cipher_pfx}")
    for c, cs, p, f in old_generate_ciphers_for_key(key, plain_pfx, cipher_pfx, fragments, words, verbose):
        print(f"c: {c}, cs: {cs}, p: {p}, frags: {f}")

    key = "fiber"
    print(f"--\nk: {key}, cp: {cipher_pfx}")
    for c, cs, p, f in old_generate_ciphers_for_key(key, plain_pfx, cipher_pfx, fragments, words, verbose):
        print(f"c: {c}, cs: {cs}, p: {p}, frags: {f}")


def main():
    args = parse_args()

    fragments = ['qvu', 'bma', 'aps', 'e', 'tn', 'nc', 'sc', 'ngqzp']
    wordlist = [ "balls", "boobs", "bonfire", "bucket", "fire", "fiber", "fandango" ]
    wordlist.sort()

    test_generate_ciphers(fragments, wordlist) #, args.verbose)
    test_generate_ciphers2(fragments, wordlist) #, args.verbose)

    wordlist = load_wordlist(args.dict, args.min_word_length)
    words = Words(set=set(wordlist), list=wordlist)
    test_generate_ciphers_for_key(fragments, words, args.verbose)


if __name__ == "__main__":
    main()
