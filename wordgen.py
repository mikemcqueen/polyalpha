from collections import namedtuple
from codec import decode_with_key
from util import join, safe_len
from context import Pkc, Context

Words = namedtuple('Words', ['set', 'list'])

all_plain_words = set()
all_key_words = set()

def get_prefix_start_idx(prefix, wordlist):
    # Find first potential match using binary search
    left, right = 0, len(wordlist) - 1
    while left <= right:
        mid = (left + right) // 2
        if wordlist[mid] < prefix:
            left = mid + 1
        else:
            right = mid - 1
    return left

def generate_key_words(ctx, md):
    ctx_key_words = ctx.key_words or []
    existing_key = join(ctx_key_words)

    def backtrack(key_words, start_idx):
        if key_words:
            key = existing_key + join(key_words)
            plain = decode_with_key(ctx.cipher[:len(key)], key)

            if not contains_words_and_word_prefix(plain, md.words):
                return

            if len(key) >= len(ctx.cipher):
                #if (ctx.level == 1): print(f" gen_kw p: {plain}, kw: {key_words}")
                yield ctx_key_words + key_words
                return

        # Try adding one more word to the key
        for i in range(start_idx, len(md.keywords.list)):
            word = md.keywords.list[i]
            if len(word) < md.min_keylen: continue
            # Only filter first keyword on key_pfx
            if not key_words and ctx.key_pfx and not word.startswith(ctx.key_pfx):
                return
            key_words.append(word)
            yield from backtrack(key_words, start_idx)  # Allow repetition of words
            key_words.pop()

    # Start backtracking with empty key
    start_idx = 0
    if ctx.key_pfx:
        start_idx = get_prefix_start_idx(ctx.key_pfx, md.keywords.list)
    yield from backtrack([], start_idx)


def generate_words_with_prefix(word_list, prefix, key_len=0):
    left, right = 0, len(word_list) - 1
    
    while left <= right:
        mid = (left + right) // 2
        if word_list[mid] < prefix:
            left = mid + 1
        else:
            right = mid - 1

    N = 2
    prev_stub = None
    start_idx = left
    end_idx = len(word_list)
    valid_stub = True
    for i in range(start_idx, end_idx):
        word = word_list[i]
        if len(word) <= len(prefix):
            continue
        if not word.startswith(prefix):
            break
        if key_len < N:
            stub = word[:N]
            if stub != prev_stub:
                prev_stub = stub
                if (i + 1 < end_idx) and (word_list[i + 1][:N] == stub):
                    valid_stub = yield stub, True
                    if valid_stub:
                        print(f"Found valid word starting with '{stub}'")
                    else:
                        print(f"No valid words starting with '{stub}'")
        if valid_stub:
            yield word, False


def generate_words(ctx, words):
    """
    Generator function that yields all possible unique valid partitions of the input string,
    where each partition uses ALL letters and satisfies these constraints:
    a) a word in the wordlist
    b) a sequence of one or more words in the wordlist
    c) a sequence of zero or more words in the wordlist, followed by characters that are
       a prefix to a word in the wordlist
    
    Args:
        input_string (str): The input string containing a sequence of letters
        wordlist (list): A list of valid words
        
    Yields:
        tuple: A tuple of format (complete_words, prefix) where:
              - complete_words is a list of words from the wordlist or None if empty
              - prefix is either a string (prefix of a word in wordlist) or None
    """
    # Use binary search approach to check if a string is a prefix
    def is_prefix_of_word(prefix):
        left, right = 0, len(words.list) - 1
        while left <= right:
            mid = (left + right) // 2
            if words.list[mid] < prefix:
                left = mid + 1
            else:
                right = mid - 1
        
        for i in range(left, len(words.list)):
            word = words.list[i]
            if not word.startswith(prefix):
                break
            if word != prefix:
                return True
        return False
    
    # Keep track of already yielded partitions to avoid duplicates
    yielded_partitions = set()
    last_idx = safe_len(ctx.plain_pfx) + len(ctx.plaintext)
    
    def backtrack(start_idx, current_words):
        # Base case: we've processed the entire input string
        if start_idx == last_idx:
            # We have a valid partition with only complete words, no prefix
            words_to_yield = list(current_words) if current_words else None
            partition = (tuple(current_words), None)
            if partition not in yielded_partitions:
                yielded_partitions.add(partition)
                #all_plain_words.add(word for word in words_to_yield)
                yield words_to_yield, None
            return
        
        # Try to find full words starting at current position
        for end_idx in range(start_idx + 1, len(ctx.plaintext) + 1):
            current_substring = (ctx.plain_pfx or "") if start_idx == 0 else ""
            current_substring += ctx.plaintext[start_idx:end_idx]
            
            # Check if the current substring is a valid word
            if current_substring in words.set:
                # Add this word to our current parts and continue
                current_words.append(current_substring)
                # Recurse to find more words
                yield from backtrack(end_idx, current_words)
                # Backtrack
                current_words.pop()
        
        # Check if the remaining substring is a valid prefix
        remaining = ctx.plaintext[start_idx:]
        if is_prefix_of_word(remaining):
            # If current_words is empty, yield None instead of an empty list
            words_to_yield = list(current_words) if current_words else None
            partition = (tuple(current_words), remaining)
            if partition not in yielded_partitions:
                yielded_partitions.add(partition)
                yield words_to_yield, remaining
    
    # Single word case (constraint a)
    whole_word = (ctx.plain_pfx or "") + ctx.plaintext
    if whole_word in words.set:
        partition = (tuple([whole_word]), None)
        if partition not in yielded_partitions:
            yielded_partitions.add(partition)
            yield [whole_word], None
    
    # Start backtracking from the beginning of the string with no current words
    yield from backtrack(0, [])


def is_empty_generator(gen):
    for _ in gen:
        return False
    return True

def keyword_generator(ctx, md):
    return generate_key_words(ctx, md)

def can_generate_keyword(ctx, md):
    return not is_empty_generator(keyword_generator(ctx, md))

def contains_words_and_word_prefix(text, words):
    ctx = Context(plaintext=text)
    for _ in generate_words(ctx, words):
        return True
    return False


def show_all_words():
    print("key\n-----")
    print(word for word in all_key_words)
    print("\nplain\n-----")
    print(word for word in all_plain_words)

"""
--do--
word: do
word: dog
word: dogmeat
--bonfi--
word: bonfire
"""
def test_generate_words_with_prefix(wordlist):
    prefix = "do"
    print(f"--{prefix}--")
    for word in generate_words_with_prefix(wordlist, prefix):
        print(f"word: {word}")

    prefix = "bonfi"
    print(f"--{prefix}--")
    cipher_prefix = "xzfdq"
    wordlist = [ "balls", "boobs", "bonfire", "bucket" ]
    wordlist.sort()
    for word in generate_words_with_prefix(wordlist, prefix):
        print(f"word: {word}")


"""
Valid partitions for input 'applecatdog':
words: ['apple', 'cat', 'do'], prefix: g
words: ['apple', 'cat', 'dog'], prefix: None
words: ['apple', 'cat'], prefix: dog
"""
def test_generate_words(words):
    sample_input = "applecatdog"
    
    print(f"Valid partitions for input '{sample_input}':")
    for words, prefix in generate_words(sample_input, words):
        print(f"words: {words}, prefix: {prefix}")


# Example usage:
if __name__ == "__main__":
    wordlist = ["cat", "apple", "cats", "do", "dog", "dogmeat", "go", "good"]
    wordlist.sort()
    test_generate_words_with_prefix(wordlist)
    words = Words(set=set(wordlist), list=wordlist)
    test_generate_words(words)
