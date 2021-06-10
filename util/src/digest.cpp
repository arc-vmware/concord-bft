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

#include "digest.hpp"
#include "assertUtils.hpp"

#include "digestutils.hpp"

namespace concord {
namespace util {

Digest::Digest(char* buf, size_t len) { DigestUtil::compute(buf, len, (char*)d, BLOCK_DIGEST_SIZE); }

std::string Digest::toString() const {
  char c[BLOCK_DIGEST_SIZE * 2];
  char t[3];
  static_assert(sizeof(t) == 3, "");
  for (size_t i = 0; i < BLOCK_DIGEST_SIZE; i++) {
    // TODO(DD): Is it by design?
    // NOLINTNEXTLINE(bugprone-signed-char-misuse)
    unsigned int b = (unsigned char)d[i];
    snprintf(t, sizeof(t), "%02X", b);
    c[i * 2] = t[0];
    c[i * 2 + 1] = t[1];
  }

  std::string ret(c, BLOCK_DIGEST_SIZE * 2);

  return ret;
}

void Digest::print() { printf("digest=[%s]", toString().c_str()); }

void Digest::calcCombination(const Digest& inDigest,
                             int64_t inDataA,
                             int64_t inDataB,
                             Digest& outDigest)  // TODO(GG): consider to change this function (TBD - check security)
{
  const size_t X = ((BLOCK_DIGEST_SIZE / sizeof(uint64_t)) / 2);

  memcpy(outDigest.d, inDigest.d, BLOCK_DIGEST_SIZE);

  uint64_t* ptr = (uint64_t*)outDigest.d;
  size_t locationA = ptr[0] % X;
  size_t locationB = (ptr[0] >> 8) % X;
  ptr[locationA] = ptr[locationA] ^ (inDataA);
  ptr[locationB] = ptr[locationB] ^ (inDataB);
}

void Digest::digestOfDigest(const Digest& inDigest, Digest& outDigest) {
  DigestUtil::compute(inDigest.d, sizeof(Digest), outDigest.d, sizeof(Digest));
}

}  // namespace util
}  // namespace concord