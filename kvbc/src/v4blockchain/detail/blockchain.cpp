// Concord
//
// Copyright (c) 2022 VMware, Inc. All Rights Reserved.
//
// This product is licensed to you under the Apache 2.0 license (the
// "License").  You may not use this product except in compliance with the
// Apache 2.0 License.
//
// This product may include a number of subcomponents with separate copyright
// notices and license terms. Your use of these subcomponents is subject to the
// terms and conditions of the subcomponent's license, as noted in the LICENSE
// file.

#include "v4blockchain/detail/blockchain.h"
#include "v4blockchain/detail/column_families.h"
#include "Logger.hpp"

namespace concord::kvbc::v4blockchain::detail {

Blockchain::Blockchain(const std::shared_ptr<concord::storage::rocksdb::NativeClient>& native_client)
    : native_client_{native_client} {
  if (native_client->createColumnFamilyIfNotExisting(v4blockchain::detail::BLOCKS_CF)) {
    LOG_INFO(V4_BLOCK_LOG, "Created [" << v4blockchain::detail::BLOCKS_CF << "] column family for the main blockchain");
  }
  auto last_reachable_block_id = loadLastReachableBlockId();
  if (last_reachable_block_id) {
    last_reachable_block_id_ = last_reachable_block_id.value();
    LOG_INFO(V4_BLOCK_LOG, "Last reachable block was loaded from storage " << last_reachable_block_id_);
  }
  auto genesis_blockId = loadGenesisBlockId();
  if (genesis_blockId) {
    genesis_block_id_ = genesis_blockId.value();
    LOG_INFO(CAT_BLOCK_LOG, "Genesis block was loaded from storage " << genesis_block_id_);
  }
}

/*
1 - define the id of the new block
2 - calculate the digest of the previous block
3 - create the block,  add the updates and digest to it.
4 - put it in the write batch.
5 - save the block buffer for the next block digest calculation.
Note - the increment for the  last_reachable_block_id_ is done after the write batch was written to storage.
*/
BlockId Blockchain::addBlock(const concord::kvbc::categorization::Updates& category_updates,
                             storage::rocksdb::NativeWriteBatch& wb) {
  BlockId id = last_reachable_block_id_ + 1;
  // If future from the previous add exist get its value
  concord::util::digest::BlockDigest digest;
  if (future_digest_) {
    ++from_future;
    digest = future_digest_->get();
  } else {
    ++from_storage;
    digest = calculateBlockDigest(last_reachable_block_id_);
  }
  auto blockKey = generateKey(id);
  v4blockchain::detail::Block block;
  block.addUpdates(category_updates);
  block.addDigest(digest);
  wb.put(v4blockchain::detail::BLOCKS_CF, blockKey, block.getBuffer());
  future_digest_ = thread_pool_.async(
      [](BlockId id, v4blockchain::detail::Block&& block) { return block.calculateDigest(id); }, id, std::move(block));
  return id;
}

concord::util::digest::BlockDigest Blockchain::calculateBlockDigest(concord::kvbc::BlockId id) const {
  if (id < concord::kvbc::INITIAL_GENESIS_BLOCK_ID) {
    concord::util::digest::BlockDigest empty_digest;
    empty_digest.fill(0);
    return empty_digest;
  }
  auto block_str = getBlockData(id);
  ConcordAssert(block_str.has_value());
  return v4blockchain::detail::Block::calculateDigest(id, block_str->c_str(), block_str->size());
}

std::optional<std::string> Blockchain::getBlockData(concord::kvbc::BlockId id) const {
  auto blockKey = generateKey(id);
  return native_client_->get(v4blockchain::detail::BLOCKS_CF, blockKey);
}

// get the closest key to MAX_BLOCK_ID
std::optional<BlockId> Blockchain::loadLastReachableBlockId() {
  auto itr = native_client_->getIterator(v4blockchain::detail::BLOCKS_CF);
  itr.seekAtMost(generateKey(MAX_BLOCK_ID));
  if (!itr) {
    return std::optional<BlockId>{};
  }
  return concordUtils::fromBigEndianBuffer<BlockId>(itr.keyView().data());
}

// get the closest key to INITIAL_GENESIS_BLOCK_ID
std::optional<BlockId> Blockchain::loadGenesisBlockId() {
  auto itr = native_client_->getIterator(detail::BLOCKS_CF);
  itr.seekAtLeast(generateKey(concord::kvbc::INITIAL_GENESIS_BLOCK_ID));
  if (!itr) {
    return std::optional<BlockId>{};
  }
  return concordUtils::fromBigEndianBuffer<BlockId>(itr.keyView().data());
}

}  // namespace concord::kvbc::v4blockchain::detail
