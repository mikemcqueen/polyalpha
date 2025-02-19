#include <numeric>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>
#include <unordered_set>
#include <ranges>
#include <algorithm>
#include <fstream>
#include <coroutine>
#include <memory>
#include <optional>
#include <functional>
#include <cassert>

using StringCRef = std::reference_wrapper<const std::string>;

struct StringHash {
    using is_transparent = void; 
    size_t operator()(std::string_view sv) const { 
        return std::hash<std::string_view>{}(sv); 
    }
    size_t operator()(const std::string& s) const {
        return std::hash<std::string_view>{}(s);
    }
};
struct StringEqual {
    using is_transparent = void;
    bool operator()(std::string_view lhs, std::string_view rhs) const {
        return lhs == rhs;
    }
};

using UnorderedStringSet = std::unordered_set<std::string, StringHash, StringEqual>;

int first_word_count{};
uint64_t num_keys{};

void print_words(
    std::string_view header, const std::vector<StringCRef>& words) {
  printf("%s: ", header.data());
  for (const auto word : words) { printf("%s ", word.get().c_str()); }
  puts("");
}

template<typename T>
class Generator {
public:
  struct promise_type {
    std::optional<T> value;  // Store as optional to avoid default construction
    Generator get_return_object() {
      return Generator(handle_type::from_promise(*this));
    }
    std::suspend_always initial_suspend() { return {}; }
    std::suspend_always final_suspend() noexcept { return {}; }
    template <std::convertible_to<T> From>
    std::suspend_always yield_value(From&& from) {
      value.emplace(std::forward<From>(from));
      return {};
    }
    void return_void() {}
    void unhandled_exception() { throw; }
  };

  using handle_type = std::coroutine_handle<promise_type>;

  Generator(handle_type h) : coro(h) {}
  ~Generator() {
    if (coro) coro.destroy();
  }

  Generator(const Generator&) = delete;
  Generator& operator=(const Generator&) = delete;

  Generator(Generator&& other) noexcept : coro(other.coro) {
    other.coro = nullptr;
  }

  Generator& operator=(Generator&& other) noexcept {
    if (this != &other) {
      if (coro) coro.destroy();
      coro = other.coro;
      other.coro = nullptr;
    }
    return *this;
  }

  bool next() {
    if (coro) {
      coro.resume();
      return !coro.done();
    }
    return false;
  }

  const T& current_value() const { return *coro.promise().value; }

private:
    handle_type coro;
};

struct DecodingResult {
  std::string encoded;
  std::reference_wrapper<const std::vector<StringCRef>> key_words;
  std::string text;
  std::reference_wrapper<const std::vector<StringCRef>> valid_words;
  int result_num;

  DecodingResult(const std::string en, const std::vector<StringCRef>& kw,
      std::string dt, const std::vector<StringCRef>& vw, int rn)
      : encoded(en), key_words(kw), text(std::move(dt)), valid_words(vw),
        result_num(rn) {}
};

class TextDecoder {
public:
  TextDecoder(const std::vector<std::string>& fragments,
      const std::string& wordlist_path, size_t min_word_length = 1)
      : fragments_(fragments), min_word_len_(min_word_length) {
    target_len_ = std::accumulate(fragments_.begin(), fragments_.end(), 0ULL,
        [](size_t sum, const std::string& s) { return sum + s.length(); });

    // Pre-allocate working vectors
    current_key_words_.reserve(target_len_);
    current_valid_words_.reserve(target_len_);
    std::vector<StringCRef> cp;
    for (int idx{}; const auto& frag: fragments_) {
      current_permutation_.push_back(idx++);
    }
    load_wordlist(wordlist_path);
  }

  Generator<DecodingResult> process_all() {
    int num_perms{};
    do {
      reset_perm_state();
      if (!(++num_perms % 100)) {
        printf("\rperms: %d", num_perms);
        fflush(stdout);
      }
      std::string encoded;
      encoded.reserve(target_len_);
      for (const auto idx : current_permutation_) {
        encoded += fragments_[idx];
      }
      //printf("frags: %s\n", encoded.c_str());
      int num_valid_keys{};
      for (auto maybe_result = generate_key_combinations(encoded, 0);
          maybe_result.has_value();
          maybe_result = try_next_combination(encoded)) {
        /*
        ++num_valid_keys;
        if (!(num_keys % 100)) {
          printf("\r keys: %d", num_valid_keys);
          fflush(stdout);
        }
        */
        co_yield std::move(*maybe_result);
      }
    } while (std::ranges::next_permutation(current_permutation_).found);
  }

private:
  const std::vector<std::string>& fragments_;
  std::vector<std::string> wordlist_;
  std::vector<size_t> letter_start_indices_;
  UnorderedStringSet wordlist_set_;
  size_t target_len_;
  size_t min_word_len_;
  size_t max_word_len_ = 10;
  int result_num_;
  int max_decoded_trigrams_ = 4;
  int num_decoded_trigrams_;

  // Working vectors that we'll reuse
  std::vector<int> current_permutation_;
  std::vector<StringCRef> current_key_words_;
  std::vector<StringCRef> current_valid_words_;

  void reset_perm_state() {
      current_key_words_.clear();
      result_num_ = 0;
  }

  auto is_all_alpha(const std::string& word) {
    return std::find_if_not(word.begin(), word.end(), [](char c) {
      return std::isalpha(c);
    }) == word.end();
  }

  bool contains_any_of(std::string_view str, std::string_view letters) {
    return std::ranges::any_of(str, [&letters](char c) {
        return letters.find(c) != std::string_view::npos;
    });
  }

  auto build_alphabet_index(const std::vector<std::string>& words) {
    std::vector<size_t> indices(27);
    char next_letter = 'a';
    for (size_t i{}; i < words.size(); ++i) {
      char first_char = words[i][0];
      if (first_char >= next_letter) {
        indices[first_char - 'a'] = i;
        next_letter = first_char + 1;
      }
    }
    indices[26] = words.size();
    assert(std::find(std::next(indices.begin()), indices.end(), 0) == indices.end());
    return indices;
  }

  void load_wordlist(const std::string& path) {
    std::ifstream file(path);
    if (!file) {
      throw std::runtime_error("Failed to open wordlist file: " + path);
    }
    std::string word;
    while (std::getline(file, word)) {
      word.erase(0, word.find_first_not_of(" \t\n\r\f\v"));
      word.erase(word.find_last_not_of(" \t\n\r\f\v") + 1);
      if (!word.empty() && (word.length() >= 3) && is_all_alpha(word)
          && contains_any_of(word, "aeiouy")) {
        wordlist_.push_back(std::move(word));
      }
    }
    std::vector<std::string> small_words = {"a", "in", "on", "of", "by", "to",
        "up", "at", "or", "it", "an", "no", "do", "be", "go", "is", "as"};
    for (const auto& word: small_words) {
      wordlist_.push_back(word);
    }
    // TODO: insert(begin, end)?
    for (const auto& word: wordlist_) {
        wordlist_set_.insert(word);
    }
    std::ranges::sort(wordlist_);
    letter_start_indices_ = build_alphabet_index(wordlist_);
  }

  bool add_key_word(
      const std::string& word, const std::string& encoded, size_t length) {
    current_key_words_.emplace_back(std::cref(word));
    std::string key;
    for (const auto& word : current_key_words_) { key += word; }
    auto decoded = decode_with_key(encoded, key);
    return verify_decoded_text(decoded);
  }

  void remove_key_word() {
    current_key_words_.pop_back();
  }

  std::optional<DecodingResult>
  generate_key_combinations(const std::string& encoded, size_t current_length) {
    const bool log = false;
    if (current_length == target_len_) {
      std::string key;
      key.reserve(target_len_);
      if constexpr (log) printf(" key: ");
      for (const auto& word : current_key_words_) {
        if constexpr (log) printf(" %s", word.get().c_str());
        key += word;
      }
      if constexpr (log) printf(": %s\n", key.c_str());
      auto decoded = decode_with_key(encoded, key);
      if (verify_decoded_text(decoded)) {
        return DecodingResult(encoded, current_key_words_, std::move(decoded),
            current_valid_words_, ++result_num_);
      }

      return std::nullopt;
    }

    size_t remaining = target_len_ - current_length;
    if (remaining < min_word_len_) { return std::nullopt; }

    for (const auto& word : wordlist_set_) {
      if (word.length() <= remaining) {
        if (add_key_word(word, encoded, current_length)) {
          auto result = generate_key_combinations(
              encoded, current_length + word.length());
          if (result.has_value()) { return result; }
        }
        remove_key_word();
      }
    }
    return std::nullopt;
  }

  std::optional<DecodingResult>
  try_next_combination(const std::string& encoded) {
    if (current_key_words_.size() < 2) { return std::nullopt; }

    //print_words("next keys", current_key_words_);

    // Remove last word and calculate new length
    size_t current_length = target_len_;
    current_length -= current_key_words_.back().get().length();
    current_key_words_.pop_back();

    // Try combinations with the next words
    auto it = wordlist_set_.find(current_key_words_.back().get());
    current_length -= current_key_words_.back().get().length();
    current_key_words_.pop_back();

    assert(it != wordlist_set_.end());
    for (++it; it != wordlist_set_.end(); ++it) {
      if (it->length() <= target_len_ - current_length) {
        if (add_key_word(*it, encoded, current_length)) {
          auto result =
              generate_key_combinations(encoded, current_length + it->length());
          if (result.has_value()) { return result; }
        }
        remove_key_word();
      }
    }
    return std::nullopt;
  }

  std::string decode_with_key(
      const std::string& encoded_text, const std::string& key) {
    std::string decoded;
    size_t key_pos{};
    for (auto c : encoded_text) {
      auto key_val = static_cast<uint8_t>(key[key_pos] - 'a');
      auto c_pos = static_cast<uint8_t>(c - 'a');
      auto decoded_pos = static_cast<uint8_t>((key_val - c_pos + 26) % 26);
      decoded += static_cast<char>(decoded_pos + 'a');
      key_pos = (key_pos + 1) % key.length();
    }
    return decoded;
  }

  bool verify_decoded_text(std::string_view text) {
    //print_words("keys", current_key_words_);
    current_valid_words_.clear();
    num_decoded_trigrams_ = 0;
    return find_solution(text);
  }

  bool add_valid_word(const std::string& word) {
    if (word.length() == 3) ++num_decoded_trigrams_;
    current_valid_words_.emplace_back(std::cref(word));
    return true;
  }

  void remove_last_valid_word() {
    const auto& word = current_valid_words_.back().get();
    if (word.length() == 3) --num_decoded_trigrams_;
    current_valid_words_.pop_back();
  }

  bool find_solution(std::string_view text, size_t length = 0) {
    assert(!text.empty());
    assert(length < target_len_);
    if (text.length() < min_word_len_) return false;

    auto is_candidate = text.length() + length == target_len_;
    auto max = std::min(max_word_len_, text.length());
    if (is_candidate && (max < min_word_len_)) return false;
    for (size_t word_len = min_word_len_; word_len <= max; ++word_len) {
      if ((word_len == 3) && (num_decoded_trigrams_ == max_decoded_trigrams_))
        continue;

      auto it = wordlist_set_.find(text.substr(0, word_len));
      if (it != wordlist_set_.end()) {
        auto new_length = length + it->length();
        if (new_length == target_len_) return true;
        if (add_valid_word(*it)) {
          if (find_solution(text.substr(it->length()), new_length)) return true;
          remove_last_valid_word();
        }
      }
    }
    // bail: no partial words are allowed
    if (is_candidate) return false;
    // bail: too many characters remaining 
    if (text.length() >= max_word_len_) return false;

    auto first_letter_idx = text[0] - 'a';
    auto begin_idx = letter_start_indices_[first_letter_idx];
    auto end_idx = letter_start_indices_[first_letter_idx + 1];
    for (auto idx = begin_idx; idx < end_idx; ++idx) {
      // TODO: if (current length + word length > total length) continue;
      if (wordlist_.at(idx).starts_with(text)) {
        return true;
        /*
        current_valid_words_.emplace_back(std::cref(word));
        if (find_solution(text.substr(word.length()), length + word.length()))
          return true;
        current_valid_words_.pop_back();
        */
      }
    }
    return false;
  }
};

int main(int argc, char* argv[]) {
  std::vector<std::string> fragments = {
      "qvu", "bma", "aps", "e", "tn", "sc", "nc", "xzfdq", "ngqzp"};
//      "xzfdq", "ngqzp"};
//      "qvu", "bma", "aps", "xzfdq", "ngqzp"};

  int min_letters = 1;
  if (argc > 1) {
    min_letters = atoi(argv[1]);
  }

  //  std::string dict_path = "/usr/share/dict/words";
  std::string dict_path = "./words";
  TextDecoder decoder(fragments, dict_path, min_letters);

  auto results = decoder.process_all();
  while (results.next()) {
    auto decoded = results.current_value();
    if (decoded.result_num == 1) { printf("Encoded: %s\n", decoded.encoded.c_str()); }
    printf("Decoded: %s", decoded.text.c_str());
    print_words(": ", decoded.valid_words);
    print_words("   keys", decoded.key_words);
  }
  return 0;
}
