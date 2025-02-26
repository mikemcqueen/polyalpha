def safe_len(o):
    return 0 if o is None else len(o)

def aggregate_len(c):
    return 0 if c is None else sum(len(e) for e in c)

