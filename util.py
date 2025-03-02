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
    parser.add_argument("-d", "--dict", default="/usr/share/dict/words")
    parser.add_argument("-m", "--min-word-length", type=int, default=3)
    parser.add_argument('-v', '--verbose', action='store_true')
    parser.add_argument('-w', '--show-words', action='store_true')
    return parser.parse_args()


def join(c, d=''):
    return d.join(c)
