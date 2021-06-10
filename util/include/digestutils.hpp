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

#include <array>
#include <cstdint>
#include <set>
#include <memory>

#include "digest.hpp"

namespace concord {
namespace util {

using digest_t = std::array<std::uint8_t, BLOCK_DIGEST_SIZE>;

class DigestContext {
 public:
  DigestContext();
  void update(const char *data, size_t len);
  void writeDigest(char *outDigest);  // write digest to outDigest, and invalidate the Context object
  ~DigestContext();

 private:
  void *internalState;
};

class DigestUtil {
 private:
  static void computeBlockDigestImpl(const uint64_t blockNum,
                                     const char *block,
                                     const uint32_t blockSize,
                                     char *outDigest);

 public:
  // This method should be used to compute block digests
  static void computeBlockDigest(const uint64_t blockId,
                                 const char *block,
                                 const uint32_t blockSize,
                                 Digest *outDigest);

  static digest_t computeBlockDigest(const uint64_t blockId, const char *block, const uint32_t blockSize);

  static size_t digestLength();

  static bool compute(const char *input, size_t inputLength, char *outBufferForDigest, size_t lengthOfBufferForDigest);
};

}  // namespace util
}  // namespace concord
