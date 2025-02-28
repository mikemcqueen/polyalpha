from codec import decode_with_key, find_key
from wordgen import Words, generate_words, generate_words_with_prefix, generate_key_words
from ciphergen import generate_ciphers, generate_ciphers_for_key
from util import aggregate_len, safe_len, load_wordlist, parse_args
from collections import namedtuple
from enum import Enum
from typing import NamedTuple, Optional, List
from dataclasses import dataclass, field

Metadata = namedtuple('Metadata', ['words', 'verbose'])

#Context = namedtuple('Context', ['plain_pfx', 'key_pfx', 'cipher_pfx', 'fragments'])

class Op(Enum):
    CIPHER_FOR_KEY = 1,
    CIPHER_FOR_PLAINTEXT = 2,
    KEY_WORDS = 3,
    PLAINTEXT_WORDS = 4

@dataclass
class UsedContext:
    plain_words: List[str] = field(default_factory=list)
    key_words: List[str] = field(default_factory=list)
    cipher: str = ""

@dataclass
class Context(UsedContext):
#    plain_words: Optional[List[str]] = None
    fragments: List[str] = None
    plaintext: Optional[str] = None
    plain_pfx: Optional[str] = None
    key_pfx: Optional[str] = None
    cipher: Optional[str] = None
    used: UsedContext = None

def generate_plaintext_words(key_words, ctx, md):
    assert key_words
    key = ''.join(key_words)
    plaintext = decode_with_key(ctx.cipher, key)
    ctx = Context(
        fragments=ctx.fragments,
        cipher=ctx.cipher,
        used=ctx.used,
        key_words=key_words,
        plaintext=plaintext
    )
    yield from generate_next(Op.PLAINTEXT_WORDS, ctx, md)

def generate_next(op, ctx, md):
    match(op):
        case Op.KEY_WORDS:
            # TOOD: generate_key_words(ctx, md): requires 'cipher', checks that key words yield plaintext word/prefix
            for key_words in generate_key_words(ctx, md):
                yield from generate_plaintext_words(key_words, ctx, md)

        case Op.PLAINTEXT_WORDS:
            yield ctx

        case Op.CIPHER_FOR_KEY:
            """
            for c, c_sfx, p, f in generate_ciphers_for_key(key_word, plain_pfx, cipher_pfx, fragments, words, verbose):
                plain = decode_with_key(c, key_word)
                print(f" c: {c}, p: {p}, plain: {plain}")
                yield from generate_next(plain, None, c, f, words)
            """
            return

        case Op.CIPHER_FOR_PLAINTEXT:
            return

"""
class UsedContext(NamedTuple):
    plain_words: List[str] = []
    key_words: List[str] = []
    cipher: str = ""

class Context(UsedContext):
    fragments: List[str]
#    plain_words: Optional[List[str]] = None
    plaintext: Optional[str] = None
    plain_pfx: Optional[str] = None
    key_pfx: Optional[str] = None
    cipher: Optional[str] = None
    used: UsedContext
"""
def print_ctx(ctx, hdr=None):
    if hdr: print(hdr)
    if ctx.plaintext: print(f"p: {ctx.plaintext} ", end="")
    #print(f"{p}," if p else "", end="")
    #print(f"{plain}, c: ", end="")
    #print(f"{c}," if c else "", end="")
    if ctx.key_words: print(f"kw: {ctx.key_words} ", end="")
    if ctx.key_pfx: print(f"kp: {ctx.key_pfx} ", end="")
    if ctx.cipher: print(f"c: {ctx.cipher} ", end="")
    print("")
    #print(f"{k}," if k else "", end="")
    #print(f"{w}," if w else "", end="")
    #print(f", remain: {key_remain}" if key_remain else "")

def test_generate_next_key(fragments, md):
    """
    plain_pfx = None
    key_words = ["bon"]
    key_words_len = aggregate_len(key_words)
    key_pfx = "fi"
    cipher = "xzfdq"
    cipher_pfx = cipher[key_words_len:]
    """
    ctx = Context(
        key_words=["bon"],
        key_pfx = "f",
        cipher="xzfdq",
        fragments=fragments
    )
    #assert cipher_pfx == "dq"t
    #print(f"--\npp: {plain_pfx}, kp: {key_pfx}, cp: {cipher_pfx}")
    print_ctx(ctx, "--")
    for ctx in generate_next(Op.KEY_WORDS, ctx, md):
        #key = find_key(c, new_plain + pp)
        #print(f" pp: {pp}, kp: {kp}, cp: {cp}, frags: {f}")
        print_ctx(ctx)


def main():
    args = parse_args()

    fragments = ['qvu', 'bma', 'aps', 'e', 'tn', 'nc', 'sc', 'ngqzp']
    wordlist = [ "balls", "boobs", "bon", "bonfire", "bucket", "fire", "fiber", "epic", "snow", "soybean", "soy" ]
    wordlist.sort()
    wordset = set(wordlist)
    words = Words(set=wordset,list=wordlist)
    md = Metadata(words=words, verbose=args.verbose)
    test_generate_next_key(fragments, md)

    wordlist = load_wordlist(args.dict, args.min_word_length)
    words = Words(set=wordset,list=wordlist)
    md = Metadata(words=words, verbose=args.verbose)
    test_generate_next_key(fragments, md)

if __name__ == "__main__":
    main()
