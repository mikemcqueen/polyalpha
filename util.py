import argparse

def safe_len(o):
    return 0 if o is None else len(o)


def aggregate_len(c):
    return 0 if c is None else sum(len(e) for e in c)


def load_wordlist(path, min_word_length):
    wordlist = []
    with open(path, 'r') as f:
        for word in f:
            stripped = word.strip()
            if stripped.isalpha() and len(stripped) >= min_word_length:
                wordlist.append(stripped.lower())
    wordlist.sort()
    return wordlist


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--cipher", type=str)
    parser.add_argument("-d", "--dict", default="/usr/share/dict/words")
    parser.add_argument("--kd", type=str) # keyword-dict
    parser.add_argument("-f", "--fragments", type=str)
    parser.add_argument("--af", type=str) # add-fragments
    parser.add_argument("-g", "--generate", type=str)
    parser.add_argument("-k", "--key", type=str)
    parser.add_argument("--kw", type=str) # key-words
    parser.add_argument("--kp", type=str) # key-prefix
    parser.add_argument("-m", "--min-word-length", type=int, default=3)
    parser.add_argument("--mk", type=int, default=3) # min_keylen
    parser.add_argument("-p", "--plain", type=str)
    parser.add_argument("--pp", type=str) # plain-prefix
    parser.add_argument('-v', '--verbose', action='store_true')
    parser.add_argument('-w', '--show-words', action='store_true')
    return parser.parse_args()


def join(c, d=''):
    return d.join(c)
