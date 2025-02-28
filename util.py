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
