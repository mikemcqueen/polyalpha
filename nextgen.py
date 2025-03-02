import copy
from codec import decode_with_key, find_key
from wordgen import Words, generate_words, generate_words_with_prefix, generate_key_words #, show_all_words
from ciphergen import generate_ciphers_for_key, generate_ciphers_for_plaintext
from util import aggregate_len, safe_len, load_wordlist, parse_args, join
from collections import namedtuple
from enum import Enum
from typing import NamedTuple, Optional, List
from dataclasses import dataclass, field

Metadata = namedtuple('Metadata', ['words', 'verbose'])

all_key_words = {}
all_plain_words = {}

class Op(Enum):
    CIPHERS_FOR_KEY = 1,
    KEY_WORDS = 2,
    PLAINTEXT_WORDS = 3,
    PLAINTEXT_FOR_PREFIX = 4,
    CIPHERS_FOR_PLAINTEXT = 5

@dataclass
class Pkc:
    plaintext: str = ""
    key: str = ""
    cipher: str = ""

@dataclass
class Context(Pkc):
    fragments: List[str] = None
    plaintext: Optional[str] = None
    plain_words: Optional[List[str]] = None
    plain_pfx: Optional[str] = None
    key_words: Optional[List[str]] = None
    key_pfx: Optional[str] = None
    key_sfx: Optional[str] = None
    pkc: Pkc = field(default_factory=Pkc)
    level: int = 0

def add_key_words(ctx):
    pos = 0
    for idx, word in enumerate(ctx.key_words):
        cipher = ctx.cipher[pos:pos + len(word)]
        if word not in all_key_words:
            all_key_words[word] = set()
        all_key_words[word].add(cipher)
        pos += len(word)

def show_all_words():
    print("\nkey\n-----")
    for word, ciphers in all_key_words.items(): print(f"{word}{' ' * (10 - len(word))}: {ciphers}")
    print("plain\n-----")
    for word, ciphers in all_plain_words.items(): print(f"{word}{' ' * (10 - len(word))}: {ciphers}")

def next_key_for_cipher(cipher, fragments, ctx, md):
    ctx = copy.copy(ctx)
    ctx.cipher = cipher
    ctx.fragments = fragments
    yield from next_key_common(ctx, md)

def next_key_for_plain_word(plain_word, ctx, md):
    ctx = copy.copy(ctx)
    ctx.plaintext = plain_word
    ctx.plain_words = [plain_word]
    yield from next_key_common(ctx, md)

def next_key_common(ctx, md):
    key_len = aggregate_len(ctx.key_words)
    assert len(ctx.cipher) >= key_len #len(ctx.plaintext)
    assert len(ctx.plaintext) > key_len
    key = find_key(ctx.cipher[:len(ctx.plaintext)], ctx.plaintext)
    ctx.key_pfx = key[:key_len]
    #if md.verbose: print(f"kp: {ctx.key_pfx}")
    yield from generate_next(Op.KEY_WORDS, ctx, md)

def next_plaintext_for_prefix(plain_words, plain_pfx, ctx, md):
    assert plain_pfx
    pkc = copy.copy(ctx.pkc)
    key_words = ctx.key_words
    cipher = ctx.cipher
    if plain_words:
        plaintext = join(plain_words)
        pkc.plaintext += plaintext
        key = join(ctx.key_words)
        pkc.key += key[:len(plaintext)]
        key_words = [key[len(plaintext):]]
        pkc.cipher += ctx.cipher[:len(plaintext)]
        cipher = cipher[len(plaintext):]

    ctx = Context(
        level = ctx.level,
        fragments = ctx.fragments,
        plain_pfx = plain_pfx,
        key_words = key_words,
        cipher = cipher,
        pkc = pkc
    )
    yield from generate_next(Op.PLAINTEXT_FOR_PREFIX, ctx, md)

def next_plaintext_for_cipher(cipher, fragments, ctx, md):
    assert cipher
    key = join(ctx.key_words)
    plaintext = decode_with_key(cipher[:len(key)], key)
    ctx = Context(
        level = ctx.level,
        key_words = ctx.key_words,
        pkc = ctx.pkc,
        cipher = cipher,
        fragments = fragments,
        plaintext = plaintext
    )
    yield from generate_next(Op.PLAINTEXT_WORDS, ctx, md)

def next_plaintext_for_key(key_words, ctx, md):
    assert key_words
    key = join(key_words)
    plaintext = decode_with_key(ctx.cipher[:len(key)], key)
    ctx = Context(
        level = ctx.level,
        fragments = ctx.fragments,
        cipher = ctx.cipher,
        pkc = ctx.pkc,
        key_words = key_words,
        key = key,
        plaintext = plaintext
    )
    yield from generate_next(Op.PLAINTEXT_WORDS, ctx, md)

def next_ciphers_for_key(key_words, ctx, md):
    if not ctx.fragments: yield ctx.pkc

    assert key_words
    key = join(key_words)
    ctx = Context(
        level = ctx.level,
        fragments = ctx.fragments,
        cipher = ctx.cipher,
        pkc = ctx.pkc,
        key_words = key_words,
        key = key
    )
    yield from generate_next(Op.CIPHERS_FOR_KEY, ctx, md)

def next_ciphers_for_plain_word(plain_word, ctx, md):
    # TODO: not complete pkc here
    if not ctx.fragments: yield ctx.pkc

    assert plain_word
    ctx = copy.copy(ctx)
    ctx.plaintext = plain_word
    ctx.plain_words = [plain_word]
    yield from generate_next(Op.CIPHERS_FOR_PLAINTEXT, ctx, md)

def final_context(plain_words, key_words, ctx, md):
    print_ctx(ctx)
    hdr = None
    pkc = copy.copy(ctx.pkc)
    if ctx.plain_words:
        pkc.plaintext += join(ctx.plain_words)
    if plain_words:
        pkc.plaintext += join(plain_words)
        hdr = f"{ctx.level} pln_words"
    if ctx.key_words:
        pkc.key += join(ctx.key_words)
    if key_words:
        pkc.key += join(key_words)
        hdr = f"{ctx.level} key_words"
    if ctx.cipher:
        pkc.cipher += ctx.cipher
    return pkc, hdr

def generate_next(op, ctx, md):
    ctx.level += 1
    match(op):
        case Op.KEY_WORDS:
            #if md.verbose: print(f"{' ' * ctx.level} KEY_WORDS:{ctx.level} c: {ctx.cipher}, p: {ctx.plaintext}")
            for key_words in generate_key_words(ctx, md):
                key_len = aggregate_len(ctx.key_words) + aggregate_len(key_words)
                if key_len > len(ctx.cipher):
                    yield from next_ciphers_for_key(key_words, ctx, md)
                elif key_len > aggregate_len(ctx.plain_words): # key_len == len(ctx.cipher)
                    yield from next_plaintext_for_key(key_words, ctx, md)
                else:
                    yield final_context(None, key_words, ctx, md)

        case Op.CIPHERS_FOR_KEY:
            #if md.verbose: print(f"{' ' * ctx.level} CIPHERS_FOR_KEY:{ctx.level} k: {ctx.key_words}")
            for cipher, fragments in generate_ciphers_for_key(ctx, md):
                yield from next_plaintext_for_cipher(cipher, fragments, ctx, md)

        case Op.PLAINTEXT_WORDS:
            if md.verbose: print(f"{' ' * ctx.level} PLAINTEXT_WORDS:{ctx.level} p: {ctx.plaintext}")
            for plain_words, plain_pfx in generate_words(ctx.plaintext, md.words):
                add_key_words(ctx)
                if plain_pfx:
                    yield from next_plaintext_for_prefix(plain_words, plain_pfx, ctx, md)
                else: # next_any_cipher()
                    yield final_context(plain_words, None, ctx, md)

        case Op.PLAINTEXT_FOR_PREFIX:
            if md.verbose: print(f"{' ' * ctx.level} PLAINTEXT_FOR_PREFIX:{ctx.level} pp: {ctx.plain_pfx}")
            for plain_word in generate_words_with_prefix(md.words.list, ctx.plain_pfx):
                #if md.verbose: print(f"{' ' * ctx.level}gen_wwp pp: {ctx.plain_pfx}, w: {plain_word}, c: {ctx.cipher}")
                if len(plain_word) < len(ctx.cipher):
                    yield from next_key_for_plain_word(plain_word, ctx, md)
                else:
                    yield from next_ciphers_for_plain_word(plain_word, ctx, md)

        case Op.CIPHERS_FOR_PLAINTEXT:
            #if md.verbose: print(f"{' ' * ctx.level} CIPHERS_FOR_PLAINTEXT:{ctx.level} p: {ctx.plaintext}")
            for cipher, fragments in generate_ciphers_for_plaintext(ctx, md):
                yield from next_key_for_cipher(cipher, fragments, ctx, md)

    ctx.level -= 1


def print_ctx(ctx, hdr=None):
    if hdr: print(hdr)
    if ctx.plaintext: print(f"p: {ctx.plaintext} ", end="")
    if ctx.plaintext: print(f"pw: {ctx.plain_words} ", end="")
    if ctx.plain_pfx: print(f"pp: {ctx.plain_pf} ", end="")
    if ctx.key_words: print(f"kw: {ctx.key_words} ", end="")
    if ctx.key_pfx: print(f"kp: {ctx.key_pfx} ", end="")
    print(f"c: {ctx.cipher} f: {ctx.fragments} ")

def print_pkc(pkc, hdr=None):
    if hdr: print(hdr, end=" ")
    print(f"p: {pkc.plaintext} k: {pkc.key} c: {pkc.cipher}")

def test_generate_next_key(fragments, md):
    ctx = Context(
        key_words = ["bon"],
        key_pfx = "f",
        cipher = "xzfdq",
        fragments = fragments
    )
    print_ctx(ctx, "--")
    for pkc, hdr in generate_next(Op.KEY_WORDS, ctx, md):
        print_pkc(pkc, hdr)

def main():
    args = parse_args()

    fragments = ['qvu', 'bma', 'aps', 'e', 'tn', 'nc', 'sc', 'ngqzp']
    wordlist = [ "balls", "boobs", "bon", "bonfire", "bucket", "fire", "fiber", \
                 "epic", "snow", "soybean", "soy", "sir", "sire" ]
    wordlist.sort()
    wordset = set(wordlist)
    words = Words(set=wordset,list=wordlist)
    md = Metadata(words=words, verbose=args.verbose)
    test_generate_next_key(fragments, md)

    wordlist = load_wordlist(args.dict, args.min_word_length)
    words = Words(set=wordset,list=wordlist)
    md = Metadata(words=words, verbose=args.verbose)
    test_generate_next_key(fragments, md)

    if args.show_words: show_all_words()

if __name__ == "__main__":
    main()
