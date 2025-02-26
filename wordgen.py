def generate_words_with_prefix(word_list, prefix):
    """
    Generator that yields all words from a sorted word list that start with the given prefix.
    
    Args:
        word_list: A sorted list of words
        prefix: The prefix to match
        
    Yields:
        Words from word_list that start with prefix
    """
    # Since the list is sorted, we can use binary search to find the first match
    # Then iterate from there until we find words that don't match the prefix
    
    # Find first potential match using binary search
    left, right = 0, len(word_list) - 1
    
    while left <= right:
        mid = (left + right) // 2
        if word_list[mid] < prefix:
            left = mid + 1
        else:
            right = mid - 1
    
    # Start iterating from the first potential match
    start_idx = left
    
    # Yield all matching words
    for i in range(start_idx, len(word_list)):
        if word_list[i].startswith(prefix):
            yield word_list[i]
        elif word_list[i] > prefix and not word_list[i].startswith(prefix):
            # We've passed all potential matches since the list is sorted
            break


def generate_words(input_string, word_set, sorted_wordlist):
    """
    Generator function that yields all possible unique valid partitions of the input string,
    where each partition uses ALL letters and satisfies these constraints:
    a) a word in the wordlist
    b) a sequence of one or more words in the wordlist
    c) a sequence of zero or more words in the wordlist, followed by characters that are a prefix to a word in the wordlist
    
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
        # If prefix is a complete word, only consider it a prefix if it's a prefix of another word
        if prefix in word_set:
            # Binary search for the first word that might start with this prefix
            left, right = 0, len(sorted_wordlist) - 1
            while left <= right:
                mid = (left + right) // 2
                if sorted_wordlist[mid] < prefix:
                    left = mid + 1
                else:
                    right = mid - 1
            
            # Check the words from this position
            for i in range(left, len(sorted_wordlist)):
                word = sorted_wordlist[i]
                # If we've moved past potential matches, stop looking
                if not word.startswith(prefix[0]):
                    break
                if word != prefix and word.startswith(prefix):
                    return True
            return False
        
        # For non-words, binary search to find potential matches
        left, right = 0, len(sorted_wordlist) - 1
        while left <= right:
            mid = (left + right) // 2
            if sorted_wordlist[mid] < prefix:
                left = mid + 1
            else:
                right = mid - 1
        
        # Check the words from this position
        for i in range(left, len(sorted_wordlist)):
            word = sorted_wordlist[i]
            # If we've moved past potential matches, stop looking
            if not word.startswith(prefix[0]):
                break
            if word.startswith(prefix):
                return True
        return False
    
    # Keep track of already yielded partitions to avoid duplicates
    yielded_partitions = set()
    
    def backtrack(start_idx, current_words):
        # Base case: we've processed the entire input string
        if start_idx == len(input_string):
            # We have a valid partition with only complete words, no prefix
            words_to_yield = list(current_words) if current_words else None
            partition = (tuple(current_words), None)
            if partition not in yielded_partitions:
                yielded_partitions.add(partition)
                yield words_to_yield, None
            return
        
        # Try to find full words starting at current position
        for end_idx in range(start_idx + 1, len(input_string) + 1):
            current_substring = input_string[start_idx:end_idx]
            
            # Check if the current substring is a valid word
            if current_substring in word_set:
                # Add this word to our current parts and continue
                current_words.append(current_substring)
                # Recurse to find more words
                yield from backtrack(end_idx, current_words)
                # Backtrack
                current_words.pop()
        
        # Check if the remaining substring is a valid prefix
        remaining = input_string[start_idx:]
        if is_prefix_of_word(remaining):
            # If current_words is empty, yield None instead of an empty list
            words_to_yield = list(current_words) if current_words else None
            partition = (tuple(current_words), remaining)
            if partition not in yielded_partitions:
                yielded_partitions.add(partition)
                yield words_to_yield, remaining
    
    # Single word case (constraint a)
    if input_string in word_set:
        partition = (tuple([input_string]), None)
        if partition not in yielded_partitions:
            yielded_partitions.add(partition)
            yield [input_string], None
    
    # Start backtracking from the beginning of the string with no current words
    yield from backtrack(0, [])

def test_generate_words():
    sample_wordlist = ["cat", "apple", "cats", "do", "dog", "dogmeat", "go", "good"]
    sample_wordlist.sort()
    sample_input = "applecatdog"
    
    print(f"Valid partitions for input '{sample_input}':")
    for words, prefix in generate_words(sample_input, set(sample_wordlist), sample_wordlist):
        print(f"words: {words}, prefix: {prefix}")


def test_generate_words_with_prefix():
    sample_wordlist = ["cat", "apple", "cats", "do", "dog", "dogmeat", "go", "good"]
    sample_wordlist.sort()
    prefix = "do"
    print(f"--{prefix}--")
    for word in generate_words_with_prefix(sample_wordlist, prefix):
        print(f"word: {word}")

    prefix = "bonfi"
    print(f"--{prefix}--")
    cipher_prefix = "xzfdq"
    wordlist = [ "balls", "boobs", "bonfire", "bucket" ]
    wordlist.sort()
    for word in generate_words_with_prefix(wordlist, prefix):
        print(f"word: {word}")


# Example usage:
if __name__ == "__main__":
    test_generate_words()
    test_generate_words_with_prefix()
