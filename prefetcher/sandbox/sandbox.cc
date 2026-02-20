#include "sandbox.h"

#include <iostream>

#include "bloom.h"
#include "champsim.h"

void sandbox::prefetcher_initialize()
{
  std::cout << "[SANDBOX] RUNNING PREFETCHER" << std::endl;

  candidate_idx = 0;
  eval_accesses = 0;
  eval_hits = 0;
  reads = 0;
  writes = 0;
  // This is the max as described in the paper, start value does not matter
  // since it is recalculated every evaluation
  allowed_max_prefetches = 8;

  candidates.resize(NUM_CANDIDATES);

  // Zero out all of the candidates
  for (size_t i = 0; i < NUM_CANDIDATES; i++) {
    candidates[i].offset = offsets[i];
    candidates[i].score = 0;
    candidates[i].allowed_prefetches = 0;

    // Set the first 16 active prefetchers
    if (i < 16) {
      active_prefetchers[i] = (int)i;
      // Starting lsit of offsets is sorted
      sorted_active_prefetchers[i] = (int)i;
    }
  }

  eval_offset = candidates[active_prefetchers[candidate_idx]].offset;

  // Arbitrarily chosen values. Should store around 512 addresses max.
  //sandbox = BloomFilter(8192, 3);
}

uint32_t sandbox::prefetcher_cache_operate(uint64_t addr, uint64_t ip, bool cache_hit, uint8_t type, uint32_t metadata_in)
{
  // If the sandbox contains the addr, we have a hit! The prefetcher increases
  // its score. See section 4.5 of the paper (Detecting Streams), we need to
  // check the strides A-n, A-2n, A-3n
  constexpr size_t stream_len = 4;
  for (size_t i = 0; i < stream_len; i++) {
    uint64_t probe = addr - (i * eval_offset * 64);
    if (sandbox_filter.possibly_contains(probe))
      eval_hits++;
  }

  // Fake fetch next cache line by inserting it into the filter.
  uint64_t fake_pf_addr = addr + eval_offset * 64;
  sandbox_filter.insert(fake_pf_addr);

  eval_accesses++;
  access_type access = static_cast<access_type>(type);
  // Track access types to calculate bandwidth in next_candidate
  if (access == access_type::LOAD)
    reads++;
  else if (access == access_type::WRITE)
    writes++;

  // Eval window is 256 accesses long.
  if (eval_accesses >= 256)
    next_candidate();

  size_t issued_prefetches = 0;
  // Issue real requests if any prefetchers are allowed.
  for (int idx : sorted_active_prefetchers) {
    const Candidate& cand = candidates[idx];

    for (size_t i = 0; i < cand.allowed_prefetches && issued_prefetches < allowed_max_prefetches; i++) {
      uint64_t pf_addr = addr + ((i + 1) * cand.offset * 64);

      // Champsim API for prefetch_line using a uint64_t is deprecated... Guh.
      // Always fill this level, don't fill the LLC.
      prefetch_line(champsim::address{pf_addr}, true, 0);
      issued_prefetches++;
    }

    if (issued_prefetches >= allowed_max_prefetches)
      break;
  }

  return metadata_in;
}

uint32_t sandbox::prefetcher_cache_fill(champsim::address addr, long set, long way, uint8_t prefetch, champsim::address evicted_addr, uint32_t metadata_in)
{
  return metadata_in;
}
