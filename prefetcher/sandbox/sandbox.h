#ifndef sandbox_H
#define sandbox_H

#include <cstdint>

#include "address.h"
#include "bloom.h"
#include "champsim.h"
#include "modules.h"

#define CUTOFF_LOW 256
#define CUTOFF_MED 512
#define CUTOFF_HI 768

struct Candidate {
  int offset;                 // -16 to +16
  uint64_t score;             // accuracy score, 0 to 1024 within a given eval period
  uint8_t allowed_prefetches; // 0-3, depending on CUTOFF_LOW thru CUTOFF_HI
};

struct sandbox : public champsim::modules::prefetcher {
private:
  static constexpr int NUM_CANDIDATES = 32;

  // Order of offsets to consider
  static constexpr int offsets[32] = {
      1, -1, 2, -2, 3, -3, 4, -4, 5, -5, 6, -6, 7, -7, 8, -8, 9, -9, 10, -10, 11, -11, 12, -12, 13, -13, 14, -14, 15, -15, 16, -16,
  };

  // Candidate pool for an entire round.
  std::vector<Candidate> candidates;
  std::array<int, 16> active_prefetchers;
  // Idx for the current candidate
  int candidate_idx;
  int offset_idx;

  // Candidate offset being considered, -16 to +16
  int eval_offset;
  // Counter up to 256 for the current eval window
  int eval_accesses;
  // Counter up to 1024 for the current eval window
  // Placed into the correct `Candidate` upon finishing an eval period
  int eval_hits;

  // Bloom filter for the current candidate
  BloomFilter sandbox;

  void next_candidate()
  {
    // Reset for the next eval period
    sandbox.clear();
    int idx = active_prefetchers[candidate_idx];

    // Store state to be considered during prefetching
    candidates[idx].score = eval_hits;

    if (eval_hits > CUTOFF_HI)
      candidates[idx].allowed_prefetches = 3;
    else if (eval_hits > CUTOFF_MED)
      candidates[idx].allowed_prefetches = 2;
    else if (eval_hits > CUTOFF_LOW)
      candidates[idx].allowed_prefetches = 1;
    else
      candidates[idx].allowed_prefetches = 0;

    // Reset the current state
    eval_accesses = 0;
    eval_hits = 0;

    candidate_idx = candidate_idx + 1;

    if (candidate_idx >= 16) {
      // Begin a new round.
      cycle_candidates();
      candidate_idx = 0;
    }

    eval_offset = candidates[active_prefetchers[candidate_idx]].offset;
  }

  void cycle_candidates()
  {
    // Sort prefetchers by performance, so we can remove the bottom 4
    // (according to section 4.3)
    std::sort(active_prefetchers.begin(), active_prefetchers.end(), [&](int a, int b) { return candidates[a].score > candidates[b].score; });

    std::vector<int> new_candidates;
    for (int i = 0; i < candidates.size() && new_candidates.size() < 4; i++)
      if (std::find(active_prefetchers.begin(), active_prefetchers.end(), i) == active_prefetchers.end())
        new_candidates.push_back(i);

    // The idx of the 4 worst prefetchers will be at the end of
    // active_prefetchers, replace them with the new ones
    for (int i = 0; i < 4; i++) {
      int slot = active_prefetchers.size() - 4 + i;
      active_prefetchers[slot] = new_candidates[i];
    }

    // Reset the scores for all prefetchers being evaluated again
    for (int i = 0; i < active_prefetchers.size(); i++) {
      int idx = active_prefetchers[i];
      candidates[idx].score = 0;
      candidates[idx].allowed_prefetches = 0;
    }
  }

public:
  using champsim::modules::prefetcher::prefetcher;

  void prefetcher_initialize();

  uint32_t prefetcher_cache_operate(uint64_t addr, uint64_t ip, bool cache_hit, uint8_t type, uint32_t metadata_in);

  uint32_t prefetcher_cache_fill(champsim::address addr, long set, long way, uint8_t prefetch, champsim::address evicted_addr, uint32_t metadata_in);
};

#endif
