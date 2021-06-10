// Concord
//
// Copyright (c) 2018 VMware, Inc. All Rights Reserved.
//
// This product is licensed to you under the Apache 2.0 license (the "License").  You may not use this product except in
// compliance with the Apache 2.0 License.
//
// This product may include a number of subcomponents with separate copyright notices and license terms. Your use of
// these subcomponents is subject to the terms and conditions of the subcomponent's license, as noted in the LICENSE
// file.

#include "digestutils.hpp"
#include "assertUtils.hpp"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
#include <cryptopp/dll.h>
#pragma GCC diagnostic pop

#include "digesttype.hpp"

using namespace CryptoPP;
using namespace std;

#if defined MD5_DIGEST
#include <cryptopp/md5.h>
#define DigestType Weak1::MD5
#elif defined SHA256_DIGEST
#define DigestType SHA256
#elif defined SHA512_DIGEST
#define DigestType SHA512
#endif

namespace concord {
namespace util {

DigestContext::DigestContext() {
  DigestType* p = new DigestType();
  internalState = p;
}

void DigestContext::update(const char* data, size_t len) {
  ConcordAssert(internalState != nullptr);
  DigestType* p = (DigestType*)internalState;
  p->Update((CryptoPP::byte*)data, len);
}

void DigestContext::writeDigest(char* outDigest) {
  ConcordAssert(internalState != nullptr);
  DigestType* p = (DigestType*)internalState;
  SecByteBlock digest(DigestType::DIGESTSIZE);
  p->Final(digest);
  const CryptoPP::byte* h = digest;
  memcpy(outDigest, h, DigestType::DIGESTSIZE);

  delete p;
  internalState = nullptr;
}

DigestContext::~DigestContext() {
  if (internalState != nullptr) {
    DigestType* p = (DigestType*)internalState;
    delete p;
    internalState = nullptr;
  }
}

void DigestUtil::computeBlockDigestImpl(const uint64_t blockNum,
                                        const char* block,
                                        const uint32_t blockSize,
                                        char* outDigest) {
  ConcordAssertGT(blockNum, 0);
  ConcordAssertGT(blockSize, 0);
  ConcordAssert(outDigest != nullptr);
  DigestContext c;
  c.update(reinterpret_cast<const char*>(&blockNum), sizeof(blockNum));
  c.update(block, blockSize);
  c.writeDigest(outDigest);
}

void DigestUtil::computeBlockDigest(const uint64_t blockId,
                                    const char* block,
                                    const uint32_t blockSize,
                                    Digest* outDigest) {
  ConcordAssert(outDigest != nullptr);
  DigestUtil::computeBlockDigestImpl(blockId, block, blockSize, outDigest->getForUpdate());
}

digest_t DigestUtil::computeBlockDigest(const uint64_t blockId, const char* block, const uint32_t blockSize) {
  digest_t outDigest;
  DigestUtil::computeBlockDigestImpl(blockId, block, blockSize, reinterpret_cast<char*>(outDigest.data()));
  return outDigest;
}

size_t DigestUtil::digestLength() { return DigestType::DIGESTSIZE; }

bool DigestUtil::compute(const char* input,
                         size_t inputLength,
                         char* outBufferForDigest,
                         size_t lengthOfBufferForDigest) {
  DigestType dig;

  size_t size = dig.DigestSize();

  if (lengthOfBufferForDigest < size) return false;

  SecByteBlock digest(size);

  dig.Update((CryptoPP::byte*)input, inputLength);
  dig.Final(digest);
  const CryptoPP::byte* h = digest;
  memcpy(outBufferForDigest, h, size);

  return true;
}

}  // namespace util
}  // namespace concord
