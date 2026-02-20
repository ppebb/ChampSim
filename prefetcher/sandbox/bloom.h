#pragma once

#include <cstdint>
#include <stdexcept>
#include <vector>

#define FNV_OFFSET 14695981039346656037ULL
#define FNV_PRIME 1099511628211ULL

class BloomFilter
{
private:
  std::vector<uint8_t> bits;
  size_t num_bits;
  size_t num_hashes;

  // fnv hash impl taken from
  // https://en.wikipedia.org/wiki/Fowler%E2%80%93Noll%E2%80%93Vo_hash_function
  uint64_t fnv_hash(uint64_t key, size_t i) const
  {
    uint64_t hash = FNV_OFFSET;

    const uint8_t* key_bytes = reinterpret_cast<const uint8_t*>(&key);
    const uint8_t* i_bytes = reinterpret_cast<const uint8_t*>(&i);

    for (size_t j = 0; j < sizeof(uint64_t); j++) {
      hash ^= key_bytes[j];
      hash *= FNV_PRIME;

      hash ^= i_bytes[j];
      hash *= FNV_PRIME;
    }

    return hash % num_bits;
  }

public:
  BloomFilter() : bits(2048, false), num_bits(2048), num_hashes(3) {}

  BloomFilter(size_t bits_count, size_t hashes) : bits(bits_count, false), num_bits(bits_count), num_hashes(hashes)
  {
    if (bits_count == 0)
      throw std::invalid_argument("BloomFilter size must be > 0");
  }

  void insert(uint64_t key)
  {
    for (size_t i = 0; i < num_hashes; i++) {
      bits[fnv_hash(key, i)] = true;
    }
  }

  bool possibly_contains(uint64_t key) const
  {
    for (size_t i = 0; i < num_hashes; i++) {
      if (!bits[fnv_hash(key, i)])
        return false;
    }

    return true;
  }

  void clear() { std::fill(bits.begin(), bits.end(), false); }
};
