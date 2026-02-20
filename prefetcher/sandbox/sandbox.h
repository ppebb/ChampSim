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
  uint64_t last_eval_round;   // last round the candidate was used in
  int offset;                 // -16 to +16
  uint64_t score;             // accuracy score, 0 to 1024 within a given eval period
  uint8_t allowed_prefetches; // 0-3, depending on CUTOFF_LOW thru CUTOFF_HI
  bool is_active;             // Is this currently in the set of active prefetchers
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
  // sorted by abs size, so that the lower offset prefetchers can run first
  std::array<int, 16> sorted_active_prefetchers;
  // Idx for the current candidate
  int candidate_idx;

  // Candidate offset being considered, -16 to +16
  int eval_offset;
  // Counter up to 256 for the current eval window
  int eval_accesses;
  // Counter up to 1024 for the current eval window
  // Placed into the correct `Candidate` upon finishing an eval period
  int eval_hits;

  size_t eval_round;

  int reads;
  int writes;
  size_t allowed_max_prefetches;

  // Bloom filter for the current candidate
  BloomFilter sandbox_filter;

  void next_candidate()
  {
    int idx = active_prefetchers[candidate_idx];

    // Reset for the next eval period
    sandbox_filter.clear();

    // Store state to be considered during prefetching
    candidates[idx].score = eval_hits;
    candidates[idx].last_eval_round = eval_round;

    if (eval_hits > CUTOFF_HI)
      candidates[idx].allowed_prefetches = 3;
    else if (eval_hits > CUTOFF_MED)
      candidates[idx].allowed_prefetches = 2;
    else if (eval_hits > CUTOFF_LOW)
      candidates[idx].allowed_prefetches = 1;
    else
      candidates[idx].allowed_prefetches = 0;

    // hypothetical maximum number of prefetches.
    // 8 per cache access
    constexpr int max_prefetch_per_period = 8 * 256;

    int total = reads + writes;
    if (total == 0)
      total = 1;

    // Recalculate bandwidth as defined in section 4.4
    allowed_max_prefetches = std::max(2, std::min(8, max_prefetch_per_period / total));

    // Reset the current state
    eval_accesses = 0;
    eval_hits = 0;
    reads = 0;
    writes = 0;

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
    eval_round++;

    // Sort prefetchers by performance, so we can remove the bottom 4
    // (according to section 4.3)
    std::sort(active_prefetchers.begin(), active_prefetchers.end(), [&](int a, int b) { return candidates[a].score > candidates[b].score; });

    std::vector<int> inactive;

    // Select inactive candidates, then sort by the last eval round so we get
    // the least recently considered candidate.
    for (int i = 0; i < NUM_CANDIDATES; i++) {
      if (!candidates[i].is_active)
        inactive.push_back(i);
    }

    std::sort(inactive.begin(), inactive.end(), [&](int a, int b) { return candidates[a].last_eval_round < candidates[b].last_eval_round; });

    std::vector<int> new_candidates(inactive.begin(), inactive.begin() + 4);

    // The idx of the 4 worst prefetchers will be at the end of
    // active_prefetchers, replace them with the new ones
    for (size_t i = 0; i < 4; i++) {
      int slot = (int)(active_prefetchers.size() - 4 + i);
      // Set the replaced prefetcher to inactive
      candidates[active_prefetchers[slot]].is_active = false;
      active_prefetchers[slot] = new_candidates[i];
      int new_candidate_idx = active_prefetchers[slot];

      // Also reset stats for the new prefetchers so they will not fire until being evaluated
      candidates[new_candidate_idx].score = 0;
      candidates[new_candidate_idx].allowed_prefetches = 0;
      candidates[new_candidate_idx].is_active = true;
    }

    // Copy new round of prefetchers into sorted_active_prefetchers, then sort
    // it by offset (abs) so the lower offset candidates can be evaluated
    // first, as described in 4.4
    std::copy(active_prefetchers.begin(), active_prefetchers.end(), sorted_active_prefetchers.begin());
    std::sort(sorted_active_prefetchers.begin(), sorted_active_prefetchers.end(), [&](int a, int b) {
      int offset_a = candidates[a].offset;
      int offset_b = candidates[b].offset;
      int abs_a = std::abs(offset_a);
      int abs_b = std::abs(offset_b);
      if (abs_a != abs_b)
        return abs_a < abs_b;
      return offset_a > offset_b;
    });
  }

public:
  using champsim::modules::prefetcher::prefetcher;

  void prefetcher_initialize();

  uint32_t prefetcher_cache_operate(uint64_t addr, uint64_t ip, bool cache_hit, uint8_t type, uint32_t metadata_in);

  uint32_t prefetcher_cache_fill(champsim::address addr, long set, long way, uint8_t prefetch, champsim::address evicted_addr, uint32_t metadata_in);
};

#endif
