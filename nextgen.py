import copy
from codec import decode_with_key, find_key
from wordgen import *
from ciphergen import generate_ciphers_for_key, generate_ciphers_for_plaintext
from util import aggregate_len, safe_len, load_wordlist, parse_args, join
from collections import namedtuple
from enum import Enum
from typing import NamedTuple
from context import Pkc, Context

Metadata = namedtuple('Metadata', ['words', 'keywords', 'verbose', 'min_keylen'])

all_key_words = {}
all_plain_words = {}

class Op(Enum):
    CIPHERS_FOR_KEY = 1,
    KEY_WORDS = 2,
    PLAINTEXT_WORDS = 3,
    PLAINTEXT_FOR_PREFIX = 4,
    CIPHERS_FOR_PLAINTEXT = 5

def add_key_words(ctx):
    pos = 0
    for idx, key in enumerate(ctx.key_words):
        cipher = ctx.cipher[pos:pos + len(key)]
        if key not in all_key_words:
            all_key_words[key] = {}
        all_key_words[key][cipher] = decode_with_key(cipher, key)
        pos += len(key)

def add_plain_words(ctx, plain_words, plain_pfx):
    if plain_words:
        word = join(plain_words)
    else:
        word = plain_pfx
    if word not in all_plain_words:
        all_plain_words[word] = set()
    all_plain_words[word].add(plain_pfx)

def show_all_words():
    print("\nkey\n-----")
    keys = list(all_key_words.keys())
    keys.sort()
    #for word, ciphers in all_key_words.items(): print(f"{word}{' ' * (10 - len(word))}: {ciphers}")
    for key in keys: print(f"{key}{' ' * (10 - len(key))}: {all_key_words[key]}")

    print("\nplain\n-----")
    words = list(all_plain_words.keys())
    words.sort()
    for word in words: print(f"{word}{' ' * (10 - len(word))}: {all_plain_words[word]}")

def plain_word_ctx(plain_word, ctx, md, once=False):
    copy.copy(ctx)
    ctx.plaintext = plain_word
    ctx.plain_words = [plain_word]
    ctx.plain_pfx = None
    ctx.once = once
    return ctx

def add_key_prefix(ctx, md):
    key_len = aggregate_len(ctx.key_words)
    # i think this assertion should always matter, because we shouldn't be 
    # Once-testing plain stub if we already have [key_words].
    # Because we've already derived plaintext from key_words, which
    # essentially proves that plaintext is a valid stub.
    # (there are possibly some very short length edge cases here)
    assert len(ctx.plaintext) > key_len
    #if len(ctx.plaintext) > len(ctx.cipher):
    #    print(f"p: {ctx.plaintext}, c: {ctx.cipher}")
    # this may not be true because we may only generate ciphers 2 characters
    # longer than len(key_words) at a time, in order to short-circuit invalid
    # permutations 
    #assert len(ctx.plaintext) <= len(ctx.cipher)
    key = find_key(ctx.cipher[:len(ctx.plaintext)], ctx.plaintext)
    # need to take min here because of ctx.once condition, when testing plain stub
    # otherwise this assert would matter (presumably)
    # see above: no ctx.once test if [key_words] exists.
    #ctx.key_pfx = key[min(key_len, len(ctx.plaintext)):]
    ctx.key_pfx = key[key_len:]
    #if md.verbose: print(f"kp: {ctx.key_pfx}")
    return ctx

def key_ctx_for_cipher(cipher, fragments, ctx, md):
    ctx = copy.copy(ctx)
    ctx.cipher = cipher
    ctx.fragments = fragments
    return add_key_prefix(ctx, md)

"""
def next_key_for_plain_word(plain_word, ctx, md):
    ctx = plain_word_ctx(plain_word, ctx, md)
    add_key_prefix(ctx, md)
    value = yield from generate_next(Op.KEY_WORDS, ctx, md)
    return value

def next_key_for_cipher(cipher, fragments, ctx, md):
    ctx = copy.copy(ctx)
    ctx.cipher = cipher
    ctx.fragments = fragments
    yield from next_key_common(ctx, md)

def next_key_common(ctx, md):
    key_len = aggregate_len(ctx.key_words)
    assert len(ctx.cipher) >= key_len #len(ctx.plaintext)
    assert len(ctx.plaintext) > key_len
    key = find_key(ctx.cipher[:len(ctx.plaintext)], ctx.plaintext)
    ctx.key_pfx = key[:key_len]
    #if md.verbose: print(f"kp: {ctx.key_pfx}")
    yield from generate_next(Op.KEY_WORDS, ctx, md)
"""

def next_plaintext_for_prefix(plain_words, plain_pfx, ctx, md):
    assert plain_pfx
    pkc = copy.copy(ctx.pkc)
    key_words = ctx.key_words
    cipher = ctx.cipher
    if plain_words:
        plaintext = join(plain_words)
        pkc.plaintext += plaintext
        key = join(ctx.key_words)

        if md.verbose: print(f"{' ' * ctx.level} next_pfp k: {key}, p: {plaintext}, pp: {plain_pfx}, c: {cipher}")

        pkc.key += key[:len(plaintext)]
        key_words = [key[len(plaintext):]]
        pkc.cipher += ctx.cipher[:len(plaintext)]
        cipher = cipher[len(plaintext):]

    ctx = Context(
        level = ctx.level,
        once = ctx.once,
        fragments = ctx.fragments,
        plain_pfx = plain_pfx,
        key_words = key_words,
        cipher = cipher,
        pkc = pkc
    )
    value = yield from generate_next(Op.PLAINTEXT_FOR_PREFIX, ctx, md)
    return value

def next_plaintext_for_cipher(cipher, fragments, ctx, md):
    assert cipher
    key = join(ctx.key_words)
    plaintext = decode_with_key(cipher[:len(key)], key)
    ctx = Context(
        level = ctx.level,
        once = ctx.once,
        key_words = ctx.key_words,
        plain_pfx = ctx.plain_pfx,
        pkc = ctx.pkc,
        cipher = cipher,
        fragments = fragments,
        plaintext = plaintext
    )
    value = yield from generate_next(Op.PLAINTEXT_WORDS, ctx, md)
    return value

def next_plaintext_for_key(key_words, ctx, md):
    assert key_words
    key = join(key_words)
    plaintext = decode_with_key(ctx.cipher[:len(key)], key)
    ctx = Context(
        level = ctx.level,
        once = ctx.once,
        fragments = ctx.fragments,
        cipher = ctx.cipher,
        plain_pfx = ctx.plain_pfx,
        pkc = ctx.pkc,
        key_words = key_words,
        key = key,
        plaintext = plaintext
    )
    value = yield from generate_next(Op.PLAINTEXT_WORDS, ctx, md)
    return value

def next_ciphers_for_key(key_words, ctx, md):
    if not ctx.fragments:
        #yield ctx.pkc, "cfk"
        return False

    assert key_words
    key = join(key_words)
    ctx = Context(
        level = ctx.level,
        once = ctx.once,
        fragments = ctx.fragments,
        cipher = ctx.cipher,
        plain_pfx = ctx.plain_pfx,
        pkc = ctx.pkc,
        key_words = key_words,
        key = key
    )
    value = yield from generate_next(Op.CIPHERS_FOR_KEY, ctx, md)
    return value

"""
def next_ciphers_for_plain_word(plain_word, ctx, md):
    # TODO: not complete pkc here
    if not ctx.fragments: yield ctx.pkc, "cfpw"

    assert plain_word
    ctx = copy.copy(ctx)
    ctx.plaintext = plain_word
    ctx.plain_words = [plain_word]
    yield from generate_next(Op.CIPHERS_FOR_PLAINTEXT, ctx, md)
"""

def final_context(plain_words, key_words, ctx, md):
    #print_ctx(ctx)
    ctx.print()
    hdr = f"{ctx.level} "
    remain_len = aggregate_len(ctx.fragments)
    if remain_len == 0:
        hdr += "PERFECT "
    else:
        hdr += "FINAL "
    pkc = copy.copy(ctx.pkc)
    if ctx.plain_words:
        pkc.plaintext += join(ctx.plain_words)
    if plain_words:
        pkc.plaintext += join(plain_words)
        hdr += "pln_words"
    if ctx.key_words:
        pkc.key += join(ctx.key_words)
    if key_words:
        pkc.key += join(key_words)
        hdr += "key_words"
    if ctx.cipher:
        pkc.cipher += ctx.cipher
    return pkc, hdr

def generate_next(op, ctx, md):
    ctx.level += 1
    any_valid = False
    match(op):
        case Op.KEY_WORDS:
            if md.verbose: print(f"{' ' * ctx.level} KEY_WORDS:{ctx.level} c: {ctx.cipher}, " \
                                 f"p: {ctx.plaintext}, kw: {ctx.key_words}, kp: {ctx.key_pfx}{', Once' if ctx.once else ''}")
            key_word_generator = keyword_generator(ctx, md)
            try:
                key_words = next(key_word_generator)
                while True:
                    valid = True
                    # TODO: save aggregate_len
                    key_len = aggregate_len(ctx.key_words) + aggregate_len(key_words)
                    if key_len > len(ctx.cipher):
                        valid = yield from next_ciphers_for_key(key_words, ctx, md)
                    elif key_len > aggregate_len(ctx.plain_words): # key_len == len(ctx.cipher)
                        valid = yield from next_plaintext_for_key(key_words, ctx, md)
                    else:
                        yield final_context(None, key_words, ctx, md)
                    if valid: any_valid = True
                    if ctx.once: break
                    key_words = key_word_generator.send(valid)
            except StopIteration:
                pass

        case Op.CIPHERS_FOR_KEY:
            if md.verbose: print(f"{' ' * ctx.level} CIPHERS_FOR_KEY:{ctx.level} k: {ctx.key_words}")
            any_valid = True
            for cipher, fragments in generate_ciphers_for_key(ctx, md):
                yield from next_plaintext_for_cipher(cipher, fragments, ctx, md)

        case Op.PLAINTEXT_WORDS:
            if md.verbose: print(f"{' ' * ctx.level} PLAINTEXT_WORDS:{ctx.level} p: {ctx.plaintext}, pp: {ctx.plain_pfx}")
            any_valid = True
            for plain_words, plain_pfx in generate_words(ctx, md.words):
                add_key_words(ctx)
                add_plain_words(ctx, plain_words, plain_pfx)
                if plain_pfx:
                    yield from next_plaintext_for_prefix(plain_words, plain_pfx, ctx, md)
                else: # next_any_cipher()
                    yield final_context(plain_words, None, ctx, md)

        case Op.PLAINTEXT_FOR_PREFIX:
            if md.verbose: print(f"{' ' * ctx.level} PLAINTEXT_FOR_PREFIX:{ctx.level} pp: {ctx.plain_pfx}, c: {ctx.cipher}")
            word_generator = generate_words_with_prefix(md.words.list, ctx.plain_pfx, aggregate_len(ctx.key_words))
            try:
                plain_word, once = next(word_generator)
                while True:
                    if md.verbose: print(f"{' ' * ctx.level} gen_wwp pp: {ctx.plain_pfx}, w: {plain_word}, c: {ctx.cipher}" \
                                         f"{', Once' if once else ''}")
                    valid = True
                    plain_ctx = plain_word_ctx(plain_word, ctx, md, once)
                    if len(plain_word) <= len(ctx.cipher):
                        add_key_prefix(plain_ctx, md)
                        valid = yield from generate_next(Op.KEY_WORDS, plain_ctx, md)
                        #valid = yield from next_key_for_plain_word(plain_word, ctx, md)
                    else:
                        valid = yield from generate_next(Op.CIPHERS_FOR_PLAINTEXT, plain_ctx, md)
                    if valid: any_valid = True
                    if once: break
                    plain_word, _ = word_generator.send(valid)
            except StopIteration:
                pass
            
        case Op.CIPHERS_FOR_PLAINTEXT:
            if md.verbose: print(f"{' ' * ctx.level} CIPHERS_FOR_PLAINTEXT:{ctx.level} p: {ctx.plaintext}")
            #TODO: hardcoded literal value
            cipher_generator = generate_ciphers_for_plaintext(ctx, md, aggregate_len(ctx.key_words) + 2)
            try:
                cipher, fragments, once = next(cipher_generator)
                while True:
                    key_ctx = key_ctx_for_cipher(cipher, fragments, ctx, md)
                    valid = yield from generate_next(Op.KEY_WORDS, key_ctx, md)
                    if valid: any_valid = True
                    if ctx.once: break
                    cipher, fragments, _ = cipher_generator.send(valid)
            except StopIteration:
                pass

    ctx.level -= 1
    return any_valid

def md_init(args):
    wordlist = load_wordlist(args.dict, args.min_word_length)
    words = Words(set=set(wordlist), list=wordlist)
    keywords = words
    if args.kd:
        key_wordlist = load_wordlist(args.kd, 1) # min_key_len possibly
        keywords = Words(set=set(key_wordlist), list=key_wordlist)
    md = Metadata(words=words, keywords=keywords, verbose=args.verbose, min_keylen=args.mk)
    print(f"w: {len(md.words.list)}, kw: {len(md.keywords.list)}")
    return md

def print_pkc(pkc, hdr=None):
    if not pkc.plaintext and not pkc.key and not pkc.cipher: return
    if hdr: print(hdr, end=" ")
    print(f"p: {pkc.plaintext} k: {pkc.key} c: {pkc.cipher}")

def test_generate_next_key(fragments, md):
    ctx = Context(
        key_words = ["bon"],
        key_pfx = "f",
        cipher = "xzfdq",
        fragments = fragments
    )
    #print_ctx(ctx, "--")
    ctx.print("--")
    for pkc, hdr in generate_next(Op.KEY_WORDS, ctx, md):
        print_pkc(pkc, hdr)

def test_generate_next_key2(fragments, md):
    fragments = [ "nc", "ngqzp" ]
    ctx = Context(
        key_words = [],
        cipher = "",
        plain_pfx = "",
        fragments = fragments
    )
    #print_ctx(ctx, "--")
    ctx.print("--")
    for pkc, hdr in generate_next(Op.KEY_WORDS, ctx, md):
        print_pkc(pkc, hdr)

def test_generate_next_key3(fragments, md):
    #used = "escexzfdqqvuaps"
    fragments = [ "nc", "ngqzp" ]
    plaintext = "key"
    cipher = "uaps"
    key = find_key(cipher, plaintext)
    ctx = Context(
        key_words = [ "een" ],
        plain_words = [],
        cipher = cipher,
        plaintext = plaintext,
        fragments = fragments
    )
    #print_ctx(ctx, "--")
    ctx.print("--")
    for pkc, hdr in generate_next(Op.PLAINTEXT_WORDS, ctx, md):
        print_pkc(pkc, hdr)

def run_tests(args):
    fragments = ['qvu', 'bma', 'aps', 'e', 'tn', 'nc', 'sc', 'ngqzp']
    if args.fragments:
        if args.fragments.lower() == "none":
            fragments = []
        else:
            fragments = args.fragments.split(',')
    elif args.af: # add-fragments
        fragments += args.af.split(',')

    wordlist = [ "balls", "boobs", "bon", "bonfire", "bucket", "fire", "fiber", \
                 "fifteen", "epic", "snow", "soybean", "soy", "sir", "sire", "spy", "key" ]
    wordlist.sort()
    wordset = set(wordlist)
    words = Words(set=wordset,list=wordlist)
    md = Metadata(words=words, keywords=words, verbose=args.verbose, min_keylen=args.mk)

    test_generate_next_key(fragments, md)

    md = md_init(args)

    #test_generate_next_key(fragments, md)
    #test_generate_next_key2(fragments, md)
    #test_generate_next_key3(fragments, md) # needs work

def filter_fragments(cipher, fragments):
    #    return [frag for frag in fragments if frag not in string]
    missing_substrings = []
    working_string = cipher
    for substring in fragments:
        if substring in working_string:
            # If found, remove the substring from the working string
            working_string = working_string.replace(substring, '', 1)
            print(f"removed: {substring}, result: {working_string}")
        else:
            # If not found, add to the missing list
            missing_substrings.append(substring)
    
    return missing_substrings

def used(cipher, key):
    used = cipher[:len(key)]
    if len(cipher) > len(key):
        used += '[' + cipher[-(len(cipher) - len(key)):] + ']'
    return used

def get_fragments(args):
    fragments = ['qvu', 'bma', 'aps', 'e', 'tn', 'nc', 'sc', 'ngqzp', 'xzfdq']
    if args.fragments:
        if args.fragments.lower() == "none":
            fragments = []
        else:
            fragments = args.fragments.split(',')
    elif args.af: # add-fragments
        fragments += args.af.split(',')
    return fragments

def find(args):
    fragments = get_fragments(args)
    md = md_init(args)

    pad = 30
    if args.plain:
        ctx = Context(plaintext=args.plain, fragments=fragments)
        for cipher, fragments, once in generate_ciphers_for_plaintext(ctx, md):
            key = find_key(cipher, ctx.plaintext)
            if contains_words_and_word_prefix(key, md.keywords):
                used_cipher = used(cipher, key)
                print(f"{used_cipher}{' ' * (pad - len(used_cipher))}: {key}, f: {fragments}")

    elif args.key:        
        ctx = Context(key=args.key, fragments=fragments)
        for cipher, fragments in generate_ciphers_for_key(ctx, md):
            plain = decode_with_key(cipher[:len(ctx.key)], ctx.key)
            used_cipher = used(cipher, ctx.key)
            print(f"{used_cipher}{' ' * (pad - len(used_cipher))}: {plain}, f: {fragments}")

    elif args.cipher:
        key_words = args.kw.split(',') if args.kw else []
        #if args.kw: key_words = args.kw.split(',')
        ctx = Context(
            cipher = args.cipher,
            key_words = key_words,
            key_pfx = args.kp,
            plain_pfx = args.pp,
            fragments = filter_fragments(args.cipher, fragments)
        )
        print(f"f: {ctx.fragments}")
        last_plain = None
        for pkc, hdr in generate_next(Op.KEY_WORDS, ctx, md):
            if pkc.plaintext != last_plain:
                print_pkc(pkc, hdr)
                last_plain = pkc.plaintext
"""
        for key_words in generate_key_words(ctx, md):
            key = join(key_words)
            #print(f"k: {key}")
            plain = decode_with_key(ctx.cipher[:len(key)], key)
            if plain == last_plain:
                continue
            last_plain = plain
            if contains_words_and_word_prefix(plain, md):
                print(f"{key_words}{' ' * (20 - aggregate_len(key_words))}: {plain}")
"""
            
def get_op(gen_type):
    match gen_type:
        case "keys":
            return Op.KEY_WORDS
        case "words":
            return Op.PLAINTEXT_WORDS
        case _:
            print(f"'{gen_type}' is not an allowed --generate type. Allowed types are: keys,words")
            exit()

def generate(args):
    md = md_init(args)
    fragments = get_fragments(args)

    ctx = Context(
        key_words = args.kw.split(',') if args.kw else [],
        key_pfx = args.kp or "",
        cipher = args.cipher or "",
        plaintext = args.plain or "",
        plain_pfx = args.pp or "",
        fragments = fragments
    )
    #print_ctx(ctx, "--")
    ctx.print("--")
    for pkc, hdr in generate_next(get_op(args.generate), ctx, md):
        print_pkc(pkc, hdr)

def main():
    args = parse_args()

    if not args.generate:
        if args.plain or args.key or args.cipher:
            find(args)
        else:
            run_tests(args)
    else:
        generate(args)

    if args.show_words: show_all_words()

if __name__ == "__main__":
    main()
