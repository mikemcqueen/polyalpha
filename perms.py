import argparse
from wordgen import generate_words
from ciphergen import generate_ciphers
from codec import decode_with_key, find_key
from util import aggregate_len, safe_len, load_wordlist

# NOTE: this doesn't handle case where --uc ends in 'n'; it will
#       not differentiate between 'nc' and 'ngqzp'. we'd need a
#       'list of first_frags' to support that.
def get_remaining_fragments(cipher, frags):
    def get_frag(cipher, frags):
        for frag in frags:
            if cipher.startswith(frag):
                return frag
        return ""

    pfx = "";
    for frag in iter(lambda: get_frag(cipher, frags), ""):
        cipher = cipher[len(frag):]
        frags.remove(frag)

    if cipher:
        if cipher == 'n':
            print("cipher ends in 'n'")
            exit()
        for frag in frags:
            if frag.startswith(cipher):
                pfx = frag[len(cipher):]
                frags.remove(frag)
                break
        if not pfx:
            print(f"bad cipher: {cipher}")
            exit()

    return (pfx, frags)

def parse_args():
    parser = argparse.ArgumentParser()
    #parser.add_argument("-k", "--key", nargs="?", const=None)
    #parser.add_argument('-y', '--key-offset', type=int, default=0)
    #parser.add_argument("-p", "--plain", nargs="?", const=None)
    parser.add_argument("--pp", metavar="PLAIN_PREFIX", type=str, required=True)
    parser.add_argument("--kp", metavar="KEY_PREFIX", type=str, required=True)
    parser.add_argument("--uc", metavar="USED_CIPHER", type=str, required=True)
    parser.add_argument("-m", "--min-word-length", type=int, default=3)
    parser.add_argument("-d", "--dict", default="/usr/share/dict/words")
    parser.add_argument('-v', '--verbose', action='store_true')
    return parser.parse_args()
        
class WordFinder:
    def __init__(self, cipher_pfx, fragments, wordlist, args):
        self.cipher_pfx = cipher_pfx
        self.fragments = fragments
        self.wordlist = wordlist
        self.word_set = set(wordlist)
        self.plain_pfx = args.pp
        self.key_pfx = args.kp
        self.min_word_length = args.min_word_length
        self.max_word_length = 10

    def find_first(self, pfx):
        for i, s in enumerate(self.wordlist):
            if s.startswith(pfx):
                return i
        return None

    def contains_words_and_word_prefix(self, letters, words):
        if len(letters) < 2: 
            return (True, words, letters)
        pfx = letters[:2]
        idx = self.find_first(pfx)
        if idx is not None:
            while idx < len(self.wordlist) and self.wordlist[idx].startswith(pfx):
                word = self.wordlist[idx]
                if word.startswith(letters):
                    if len(word) == len(letters):
                        words.append(word)
                        return (True, words, None)
                    else:
                        return (True, words, letters)
                if letters.startswith(word):
                    words.append(word)
                    return self.contains_words_and_word_prefix(letters[len(word):], words)
                idx += 1
        return (False, [], None)

    def find_all_words(self):
        print(f"{type(self.wordlist)}: {len(self.wordlist)}")
        return self.find_words(self.plain_pfx, self.key_pfx, self.cipher_pfx, fragments, 0, ("", "", "", []))

    def print_state(self, level, plain, cipher, key, key_words, key_remain, pkcw):
        p, k, c, w = pkcw
        print(f"{level} p: ", end="")
        #print(f"{p}," if p else "", end="")
        print(f"{plain}, c: ", end="")
        #print(f"{c}," if c else "", end="")
        print(f"{cipher}, k: ", end="")
        #print(f"{k}," if k else "", end="")
        print(f"{key}, words: ", end="")
        #print(f"{w}," if w else "", end="")
        print(f"{key_words}", end="")
        print(f", remain: {key_remain}" if key_remain else "")


    def find_words(self, plain_pfx, key_pfx, cipher_pfx, fragments, level, pkcw):
        #if level > 0:
        #    print(f" {level} pp: {plain_pfx} kp: {key_pfx} cp: {cipher_pfx} frags: {safe_len(fragments)}")
        if not fragments: return
        for frag in fragments:
            cipher = cipher_pfx + frag
            plain_idx = self.find_first(plain_pfx)
            if plain_idx is None:
                continue
            while plain_idx < len(self.wordlist) and self.wordlist[plain_idx].startswith(plain_pfx):
                plain = self.wordlist[plain_idx]
                plain_idx += 1
                key = find_key(plain, cipher)
                #print(f"plain: {plain}, key: {key}")
                for key_words, key_remain in generate_words(key_pfx + key, self.word_set, self.wordlist):
                    key_len = aggregate_len(key_words) + safe_len(key_remain)
                    p, k, c, w = pkcw
                    #if pfx is None or safe_len(words) > 2:
                        #print(f"{level} p: {plain}, c: {cipher}, k: {key}, words: {words}", end="")
                    #self.print_state(level, plain, cipher, key_pfx + key, key_words, key_remain, pkcw)

                    if key_len < len(plain) and key_remain is not None:
                        key_words_len = aggregate_len(key_words) - safe_len(plain_pfx)
                        new_plain = plain[key_words_len:]
                        new_cipher_pfx = "" if key_remain is None else cipher[-len(key_remain):]
                        remain_frags = fragments.copy()
                        remain_frags.remove(frag)
                        state_printed = False
                        for new_cipher, new_cipher_sfx, new_plain_pfx, used_frags in \
                                generate_ciphers(new_plain, key_remain, new_cipher_pfx, self.wordlist, remain_frags):
                            if not state_printed:
                                self.print_state(level, plain, cipher, key_pfx + key, key_words, key_remain, pkcw)
                                state_printed = True

                            print(f"  pp: {new_plain}, kp: {key_remain}, cp: {new_cipher_pfx}" \
                                  f", nc: {new_cipher}, ncs: {new_cipher_sfx}, npp: {new_plain_pfx}" \
                                  f", frags: {used_frags}, k({new_cipher},{new_plain}): {find_key(new_cipher, new_plain)}")
                            if new_cipher_sfx:
                                assert new_plain_pfx
                                new_frags = remain_frags.copy()
                                for uf in used_frags:
                                    new_frags.remove(uf)
                                p += plain
                                k += key
                                c += cipher
                                if key_words is not None:
                                    w += key_words
                                self.find_words(new_plain_pfx, "", new_cipher_sfx, new_frags, level + 1, (p, k, c, w))

"""
                valid, words, remain = self.contains_words_and_word_prefix(key, [])
                if not valid:
                    continue
                if len(plain) >= self.min_word_length:
                    print(f"{level} p: {plain}, c: {cipher}, k: {key}, words: {','.join(words)}, remain: {remain}")
                else:
                    self.find_words(plain_pfx, key_pfx, cipher, fragments.copy().remove(frag), level + 1)
"""


args = parse_args()
fragments = ['ngqzp','e', 'qvu', 'bma', 'aps', 'tn', 'nc', 'sc', 'xzfdq']
cipher_pfx, fragments = get_remaining_fragments(args.uc, fragments)
print(f"cp: '{cipher_pfx}', remaining_frags: {','.join(fragments)}")
if cipher_pfx:
    if not args.pp:
        print(f"Cipher prefix '{cipher_pfx}' requires PLAIN_PREFIX")
        exit()
    # TODO: confirm decoded cipher prefix matches plain prefix
wordlist = load_wordlist(args.dict, args.min_word_length)
finder = WordFinder(cipher_pfx, fragments, wordlist, args)
finder.find_all_words()
