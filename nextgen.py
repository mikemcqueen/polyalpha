from codec import decode_with_key, find_key
from wordgen import Words, generate_words, generate_words_with_prefix
from ciphergen import generate_ciphers, generate_ciphers_for_key
from util import aggregate_len, safe_len

def generate_next(plain_pfx, key_pfx, cipher_pfx, fragments, words):
    assert bool(plain_pfx) ^ bool(key_pfx), "one must be empty (i think)"

    #    while True:
    if key_pfx:
        assert len(key_pfx) == len(cipher_pfx), "maybe required?"
        for key_word in generate_words_with_prefix(words.list, key_pfx):
            """
            if len(key_word) == len(key_pfx):
            plain = decrypt_with_key(cipher_pfx, key_word)
            yield from generate_next(plain, "", "", fragments, words)
            else
            """
            for c, c_sfx, p, f in generate_ciphers_for_key(key_word, plain_pfx, cipher_pfx, fragments, words, True):
                plain = decrypt_with_key(cipher, key_word)
                print(f" c: {c}, p: {p}, plain: {plain}")
                yield from generate_next(plain, None, c, f, words)
    else:
        yield plain_pfx, key_pfx, cipher_pfx, fragments


def test_generate_next_key(fragments, words):
    plain_pfx = None
    key_words = ["bon"]
    key_words_len = aggregate_len(key_words)
    key_pfx = "fi"
    cipher = "xzfdq"
    cipher_pfx = cipher[key_words_len:]
    assert cipher_pfx == "dq"
    print(f"--\npp: {plain_pfx}, kp: {key_pfx}, cp: {cipher_pfx}")
    for pp, kp, cp, f in generate_next(plain_pfx, key_pfx, cipher_pfx, fragments, words):
        #key = find_key(c, new_plain + pp)
        print(f" pp: {pp}, kp: {kp}, cp: {cp}, frags: {f}")


def main():
    fragments = ['qvu', 'bma', 'aps', 'e', 'tn', 'nc', 'sc', 'ngqzp']
    wordlist = [ "balls", "boobs", "bonfire", "bucket", "fire" ]
    wordlist.sort()
    wordset = set(wordlist)
    words = Words(set=wordset,list=wordlist)

    test_generate_next_key(fragments, words)

if __name__ == "__main__":
    main()
