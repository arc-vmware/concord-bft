// Concord
//
// Copyright (c) 2018 VMware, Inc. All Rights Reserved.
//
// This product is licensed to you under the Apache 2.0 license (the "License").
// You may not use this product except in compliance with the Apache 2.0
// License.
//
// This product may include a number of subcomponents with separate copyright
// notices and license terms. Your use of these subcomponents is subject to the
// terms and conditions of the subcomponent's license, as noted in the LICENSE
// file.

#pragma once

#include <memory.h>
#include <stdint.h>
#include <string>
#include <array>
#include "digesttype.hpp"

namespace concord {
namespace util {

// Each block is required to store the digest of the previous block (this digest
// is used by the state transfer to safely transfer blocks among the replicas).
// The application/storage layer is responsible to store the digests in the
// blocks.
// Blocks are numbered. The first block should be block number 1.
inline constexpr std::uint32_t BLOCK_DIGEST_SIZE = DIGEST_SIZE;

class Digest {
 public:
  Digest() { memset(d, 0, BLOCK_DIGEST_SIZE); }
  Digest(unsigned char initVal) { memset(d, initVal, BLOCK_DIGEST_SIZE); }
  Digest(const char* other) { memcpy(d, other, BLOCK_DIGEST_SIZE); }

  Digest(char* buf, size_t len);

  // NOLINTNEXTLINE(bugprone-copy-constructor-init)
  Digest(const Digest& other) { memcpy(d, other.d, BLOCK_DIGEST_SIZE); }

  bool isZero() const {
    for (uint32_t i = 0; i < BLOCK_DIGEST_SIZE; i++) {
      if (d[i] != 0) return false;
    }
    return true;
  }

  bool operator==(const Digest& other) const {
    int r = memcmp(d, other.d, BLOCK_DIGEST_SIZE);
    return (r == 0);
  }

  bool operator!=(const Digest& other) const {
    int r = memcmp(d, other.d, BLOCK_DIGEST_SIZE);
    return (r != 0);
  }

  Digest& operator=(const Digest& other) {
    memcpy(d, other.d, BLOCK_DIGEST_SIZE);
    return *this;
  }

  int hash() const {
    uint64_t* p = (uint64_t*)d;
    int h = (int)p[0];
    return h;
  }

  void makeZero() { memset(d, 0, BLOCK_DIGEST_SIZE); }

  const char* content() const { return static_cast<const char*>(d); }
  // const char* const get() const { return content; }
  char* getForUpdate() { return d; }

  std::string toString() const;

  void print();

  static void calcCombination(const Digest& inDigest, int64_t inDataA, int64_t inDataB, Digest& outDigest);

  static void digestOfDigest(const Digest& inDigest, Digest& outDigest);

 protected:
  char d[BLOCK_DIGEST_SIZE];  // BLOCK_DIGEST_SIZE should be >= 8 bytes
};

static_assert(BLOCK_DIGEST_SIZE >= sizeof(uint64_t), "Digest size should be >= sizeof(uint64_t)");
static_assert(sizeof(Digest) == BLOCK_DIGEST_SIZE, "sizeof(Digest) != DIGEST_SIZE");

inline std::ostream& operator<<(std::ostream& os, const Digest& digest) {
  os << digest.toString();
  return os;
}

}  // namespace util
}  // namespace concord
