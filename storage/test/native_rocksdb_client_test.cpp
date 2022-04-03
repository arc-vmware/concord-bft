// Concord
//
// Copyright (c) 2020 VMware, Inc. All Rights Reserved.
//
// This product is licensed to you under the Apache 2.0 license (the
// "License").  You may not use this product except in compliance with the
// Apache 2.0 License.
//
// This product may include a number of subcomponents with separate copyright
// notices and license terms. Your use of these subcomponents is subject to the
// terms and conditions of the subcomponent's license, as noted in the LICENSE
// file.

#include "gtest/gtest.h"
#include "gmock/gmock.h"

#include "memorydb/client.h"
#include "storage/db_interface.h"
#include "rocksdb/native_client.h"
#include "sliver.hpp"
#include "storage/test/storage_test_common.h"
#include "rocksdb/time_stamp_comparator.h"
#include "endianness.hpp"

#include <string_view>
#include <utility>

namespace {

using namespace concord::storage;
using namespace concord::storage::rocksdb;
using namespace ::testing;
using namespace std::literals;

class native_rocksdb_test : public Test {
  void SetUp() override {
    destroyDb();
    db = TestRocksDb::createNative();
  }

  void TearDown() override {
    destroySnapshotDb();
    destroyDb();
  }

  void destroyDb() {
    db.reset();
    ASSERT_EQ(0, db.use_count());
    cleanup();
  }

  void destroySnapshotDb() {
    snapshotDb.reset();
    ASSERT_EQ(0, snapshotDb.use_count());
    cleanup();
  }

 protected:
  std::shared_ptr<NativeClient> db;
  std::shared_ptr<NativeClient> snapshotDb;
  const std::string key{"key"};
  const std::string value{"value"};
  const std::string key1{"key1"};
  const std::string value1{"value1"};
  const std::string key2{"key2"};
  const std::string value2{"value2"};
  const std::string key3{"key3"};
  const std::string value3{"value3"};
  const std::string key4{"key4"};
  const std::string value4{"value4"};

  void getSnapshotDb(const std::string &checkPointPath) {
    destroySnapshotDb();
    snapshotDb = TestRocksDbSnapshot::createNative(checkPointPath);
  }

  template <typename T>
  static Sliver toSliver(const T &v) {
    return Sliver::copy(v.data(), v.size());
  }
};

TEST_F(native_rocksdb_test, empty_db_has_default_family_only) {
  const auto families = db->columnFamilies();
  ASSERT_EQ(families.size(), 1);
  ASSERT_EQ(*families.begin(), NativeClient::defaultColumnFamily());
}

TEST_F(native_rocksdb_test, create_families) {
  db->createColumnFamily("cf1");
  db->createColumnFamily("cf2");
  db->createColumnFamily("cf3");
  ASSERT_THAT(db->columnFamilies(),
              ContainerEq(std::unordered_set<std::string>{db->defaultColumnFamily(), "cf1", "cf2", "cf3"}));
}

TEST_F(native_rocksdb_test, creating_a_family_twice_is_an_error) {
  const auto cf = "cf"s;
  db->createColumnFamily(cf);
  ASSERT_THROW(db->createColumnFamily(cf), RocksDBException);
  ASSERT_THAT(db->columnFamilies(), ContainerEq(std::unordered_set<std::string>{db->defaultColumnFamily(), "cf"}));
}

TEST_F(native_rocksdb_test, drop_family_and_list) {
  db->createColumnFamily("cf1");
  db->createColumnFamily("cf2");
  db->dropColumnFamily("cf2");
  ASSERT_THAT(db->columnFamilies(), ContainerEq(std::unordered_set<std::string>{db->defaultColumnFamily(), "cf1"}));
}

TEST_F(native_rocksdb_test, dropping_a_family_twice_is_not_an_error) {
  const auto cf = "cf"s;
  db->createColumnFamily(cf);
  db->dropColumnFamily(cf);
  ASSERT_NO_THROW(db->dropColumnFamily(cf));
  ASSERT_THAT(db->columnFamilies(), ContainerEq(std::unordered_set<std::string>{db->defaultColumnFamily()}));
}

TEST_F(native_rocksdb_test, creating_a_family_with_options) {
  const auto cf = "cf"s;
  auto optsIn = ::rocksdb::ColumnFamilyOptions{};
  const auto originalBufferSize = optsIn.write_buffer_size;
  // Change a random option and verify it is reflected.
  ++optsIn.write_buffer_size;
  db->createColumnFamily(cf, optsIn);
  const auto optsOut = db->columnFamilyOptions(cf);
  ASSERT_EQ(optsOut.write_buffer_size, originalBufferSize + 1);
}

TEST_F(native_rocksdb_test, family_options_are_persisted) {
  const auto cf = "cf"s;
  auto optsIn = ::rocksdb::ColumnFamilyOptions{};
  const auto originalBufferSize = optsIn.write_buffer_size;
  // Change a random option and verify it is reflected.
  ++optsIn.write_buffer_size;
  db->createColumnFamily(cf, optsIn);

  // Open the DB again and verify options are persisted.
  {
    db.reset();
    const auto db2 = TestRocksDb::createNative(NativeClient::ExistingOptions{});
    const auto optsOut = db2->columnFamilyOptions(cf);
    ASSERT_EQ(optsOut.write_buffer_size, originalBufferSize + 1);
  }
}

TEST_F(native_rocksdb_test, default_family_data_is_persisted) {
  db->put(key, value);

  // Open the DB again in RW mode and verify data
  {
    db.reset();
    const auto db2 = TestRocksDb::createNative();
    const auto dbValue = db2->get(key);
    ASSERT_TRUE(dbValue.has_value());
    ASSERT_EQ(*dbValue, value);
  }

  // Open the DB again in RO mode and verify data
  {
    const auto db2 = TestRocksDb::createNative();
    const auto dbValue = db2->get(key);
    ASSERT_TRUE(dbValue.has_value());
    ASSERT_EQ(*dbValue, value);
  }
}

TEST_F(native_rocksdb_test, family_data_is_persisted) {
  const auto cf = "cf"s;
  db->createColumnFamily(cf);
  db->put(cf, key, value);

  // Open the DB again in RW mode and verify data
  {
    db.reset();
    const auto db2 = TestRocksDb::createNative();
    const auto dbValue = db2->get(cf, key);
    ASSERT_TRUE(dbValue.has_value());
    ASSERT_EQ(*dbValue, value);
  }

  // Open the DB again in RO mode and verify data
  {
    const auto db2 = TestRocksDb::createNative();
    const auto dbValue = db2->get(cf, key);
    ASSERT_TRUE(dbValue.has_value());
    ASSERT_EQ(*dbValue, value);
  }
}

TEST_F(native_rocksdb_test, single_key_api_throws_on_non_existent_family) {
  const auto cf = "cf"s;
  ASSERT_THROW(db->get(cf, key), RocksDBException);
  ASSERT_THROW(db->put(cf, key, value), RocksDBException);
  ASSERT_THROW(db->del(cf, key), RocksDBException);
}

TEST_F(native_rocksdb_test, put_in_default_family) {
  db->put(key, value);

  // Ensure key is in the default family via the non-family interface.
  {
    const auto dbValue = db->get(key);
    ASSERT_TRUE(dbValue.has_value());
    ASSERT_EQ(*dbValue, value);
  }

  // Ensure key is in the default family via the family interface.
  {
    const auto dbValue = db->get(db->defaultColumnFamily(), key);
    ASSERT_TRUE(dbValue.has_value());
    ASSERT_EQ(*dbValue, value);
  }
}

TEST_F(native_rocksdb_test, put_with_different_key_and_value_types) {
  db->put("key"sv, "value"s);
  const auto dbValue = db->get("key"s);
  ASSERT_TRUE(dbValue.has_value());
  ASSERT_EQ(*dbValue, "value");
}

TEST_F(native_rocksdb_test, del_from_default_family) {
  db->put(key, value);
  db->del(key);
  ASSERT_FALSE(db->get(key).has_value());
}

TEST_F(native_rocksdb_test, put_in_created_family) {
  const auto cf = "cf"s;
  db->createColumnFamily(cf);
  db->put(cf, key, value);
  const auto dbValue = db->get(cf, key);
  ASSERT_TRUE(dbValue.has_value());
  ASSERT_EQ(*dbValue, value);
  // Ensure the key is not the default family.
  ASSERT_FALSE(db->get(key).has_value());
}

TEST_F(native_rocksdb_test, del_from_created_family) {
  const auto cf = "cf"s;
  db->createColumnFamily(cf);
  // Put in both the default and the created one.
  db->put(key, value);
  db->put(cf, key, value);
  db->del(cf, key);
  const auto defaultValue = db->get(key);
  ASSERT_TRUE(defaultValue.has_value());
  ASSERT_EQ(*defaultValue, value);
  ASSERT_FALSE(db->get(cf, key).has_value());
}

TEST_F(native_rocksdb_test, del_non_existent_key_is_not_an_error) { ASSERT_NO_THROW(db->del(key)); }

TEST_F(native_rocksdb_test, drop_family_and_get) {
  const auto cf = "cf"s;
  db->createColumnFamily(cf);
  db->put(cf, key, value);
  db->dropColumnFamily(cf);
  ASSERT_THROW(db->get(cf, key), RocksDBException);
}

TEST_F(native_rocksdb_test, drop_family_then_create_and_ensure_empty) {
  const auto cf = "cf"s;
  db->createColumnFamily(cf);
  db->put(cf, key, value);
  db->dropColumnFamily(cf);
  db->createColumnFamily(cf);
  ASSERT_FALSE(db->get(cf, key).has_value());
}

TEST_F(native_rocksdb_test, put_in_batch_in_default_family) {
  auto batch = db->getBatch();
  batch.put(key1, value1);
  batch.put(key2, value2);
  db->write(std::move(batch));
  const auto dbValue1 = db->get(key1);
  const auto dbValue2 = db->get(key2);
  ASSERT_TRUE(dbValue1.has_value());
  ASSERT_EQ(*dbValue1, value1);
  ASSERT_TRUE(dbValue2.has_value());
  ASSERT_EQ(*dbValue2, value2);
}

TEST_F(native_rocksdb_test, put_in_batch_in_2_families) {
  const auto cf1 = "cf1"s;
  const auto cf2 = "cf2"s;
  db->createColumnFamily(cf1);
  db->createColumnFamily(cf2);
  auto batch = db->getBatch();
  batch.put(cf1, key1, value1);
  batch.put(cf1, key2, value2);
  batch.put(cf2, key2, value2);
  batch.put(cf2, key3, value3);
  db->write(std::move(batch));

  // cf1
  {
    const auto dbValue1 = db->get(cf1, key1);
    const auto dbValue2 = db->get(cf1, key2);
    ASSERT_TRUE(dbValue1.has_value());
    ASSERT_EQ(*dbValue1, value1);
    ASSERT_TRUE(dbValue2.has_value());
    ASSERT_EQ(*dbValue2, value2);
  }

  // cf2
  {
    const auto dbValue2 = db->get(cf2, key2);
    const auto dbValue3 = db->get(cf2, key3);
    ASSERT_TRUE(dbValue2.has_value());
    ASSERT_EQ(*dbValue2, value2);
    ASSERT_TRUE(dbValue3.has_value());
    ASSERT_EQ(*dbValue3, value3);
  }
}

TEST_F(native_rocksdb_test, put_in_batch_multiple_slice_value) {
  const auto cf1 = "cf1"s;
  const auto cf2 = "cf2"s;
  db->createColumnFamily(cf1);
  auto batch = db->getBatch();
  std::array<::rocksdb::Slice, 2> val{detail::toSlice(value1), detail::toSlice(value2)};
  batch.put(cf1, key1, val);
  db->write(std::move(batch));

  // We should have written the concatenation of value1 and value2 to key1
  ASSERT_EQ(value1 + value2, db->get(cf1, key1).value());
}

TEST_F(native_rocksdb_test, del_non_existent_key_in_batch_is_not_an_error) {
  auto batch = db->getBatch();
  batch.del(key);
  ASSERT_NO_THROW(db->write(std::move(batch)));
}

TEST_F(native_rocksdb_test, multiple_deletes_for_same_key_in_batch) {
  db->put(key, value);
  auto batch = db->getBatch();
  batch.del(key);
  batch.del(key);
  ASSERT_NO_THROW(db->write(std::move(batch)));
  ASSERT_FALSE(db->get(key).has_value());
}

TEST_F(native_rocksdb_test, batch_operations_honor_order) {
  // put -> delete
  {
    auto batch = db->getBatch();
    batch.put(key, value);
    batch.del(key);
    db->write(std::move(batch));
    ASSERT_FALSE(db->get(key).has_value());
  }

  // put -> delete -> put
  {
    auto batch = db->getBatch();
    batch.put(key, value);
    batch.del(key);
    batch.put(key, value2);
    db->write(std::move(batch));
    const auto dbValue = db->get(key);
    ASSERT_TRUE(dbValue.has_value());
    ASSERT_EQ(*dbValue, value2);
  }
}

TEST_F(native_rocksdb_test, put_container_in_batch_in_default_family) {
  const auto kvSet = SetOfKeyValuePairs{std::make_pair(toSliver(key1), toSliver(value1)),
                                        std::make_pair(toSliver(key2), toSliver(value2))};
  auto batch = db->getBatch();
  putInBatch(batch, kvSet);
  db->write(std::move(batch));
  const auto dbValue1 = db->get(key1);
  ASSERT_TRUE(dbValue1.has_value());
  ASSERT_EQ(*dbValue1, value1);
  const auto dbValue2 = db->get(key2);
  ASSERT_TRUE(dbValue2.has_value());
  ASSERT_EQ(*dbValue2, value2);
}

TEST_F(native_rocksdb_test, put_container_in_batch_in_a_family) {
  const auto cf = "cf"s;
  db->createColumnFamily(cf);
  const auto kvSet = SetOfKeyValuePairs{std::make_pair(toSliver(key1), toSliver(value1)),
                                        std::make_pair(toSliver(key2), toSliver(value2))};
  auto batch = db->getBatch();
  putInBatch(batch, cf, kvSet);
  db->write(std::move(batch));
  const auto dbValue1 = db->get(cf, key1);
  ASSERT_TRUE(dbValue1.has_value());
  ASSERT_EQ(*dbValue1, value1);
  const auto dbValue2 = db->get(cf, key2);
  ASSERT_TRUE(dbValue2.has_value());
  ASSERT_EQ(*dbValue2, value2);
}

TEST_F(native_rocksdb_test, del_container_in_batch_in_default_family) {
  db->put(key1, value1);
  db->put(key2, value2);
  const auto kvVec = KeysVector{toSliver(key1), toSliver(key2)};
  auto batch = db->getBatch();
  delInBatch(batch, kvVec);
  db->write(std::move(batch));
  ASSERT_FALSE(db->get(key1).has_value());
  ASSERT_FALSE(db->get(key2).has_value());
}

TEST_F(native_rocksdb_test, del_container_in_batch_in_a_family) {
  const auto cf = "cf"s;
  db->createColumnFamily(cf);
  db->put(cf, key1, value1);
  db->put(cf, key2, value2);
  const auto kvVec = KeysVector{toSliver(key1), toSliver(key2)};
  auto batch = db->getBatch();
  delInBatch(batch, cf, kvVec);
  db->write(std::move(batch));
  ASSERT_FALSE(db->get(cf, key1).has_value());
  ASSERT_FALSE(db->get(cf, key2).has_value());
}

TEST_F(native_rocksdb_test, batch_del_range_in_default_family) {
  db->put(key1, value1);
  db->put(key2, value2);
  db->put(key3, value3);
  auto batch = db->getBatch();
  batch.delRange(key1, key3);
  db->write(std::move(batch));
  ASSERT_FALSE(db->get(key1).has_value());
  ASSERT_FALSE(db->get(key2).has_value());
  const auto dbValue3 = db->get(key3);
  ASSERT_TRUE(dbValue3.has_value());
  ASSERT_EQ(*dbValue3, value3);
}

TEST_F(native_rocksdb_test, batch_del_range_in_a_family) {
  const auto cf = "cf"s;
  db->createColumnFamily(cf);
  db->put(cf, key1, value1);
  db->put(cf, key2, value2);
  db->put(cf, key3, value3);
  auto batch = db->getBatch();
  batch.delRange(cf, key1, key3);
  db->write(std::move(batch));
  ASSERT_FALSE(db->get(cf, key1).has_value());
  ASSERT_FALSE(db->get(cf, key2).has_value());
  const auto dbValue3 = db->get(cf, key3);
  ASSERT_TRUE(dbValue3.has_value());
  ASSERT_EQ(*dbValue3, value3);
}

TEST_F(native_rocksdb_test, batch_del_invalid_range_in_default_family) {
  db->put(key1, value1);
  db->put(key2, value2);
  auto batch = db->getBatch();
  batch.delRange(key3, key1);
  EXPECT_THROW(db->write(std::move(batch)), concord::storage::rocksdb::RocksDBException);
  const auto dbValue1 = db->get(key1);
  ASSERT_TRUE(dbValue1.has_value());
  ASSERT_EQ(*dbValue1, value1);
  const auto dbValue2 = db->get(key2);
  ASSERT_TRUE(dbValue2.has_value());
  ASSERT_EQ(*dbValue2, value2);
}

TEST_F(native_rocksdb_test, batch_del_invalid_range_in_a_family) {
  const auto cf = "cf"s;
  db->createColumnFamily(cf);
  db->put(cf, key1, value1);
  db->put(cf, key2, value2);
  auto batch = db->getBatch();
  batch.delRange(cf, key3, key1);
  EXPECT_THROW(db->write(std::move(batch)), concord::storage::rocksdb::RocksDBException);
  const auto dbValue1 = db->get(cf, key1);
  ASSERT_TRUE(dbValue1.has_value());
  ASSERT_EQ(*dbValue1, value1);
  const auto dbValue2 = db->get(cf, key2);
  ASSERT_TRUE(dbValue2.has_value());
  ASSERT_EQ(*dbValue2, value2);
}

TEST_F(native_rocksdb_test, batch_for_non_existent_family_throws) {
  const auto cf = "cf"s;

  {
    auto batch = db->getBatch();
    ASSERT_THROW(batch.put(cf, key, value), RocksDBException);
    ASSERT_THROW(batch.del(cf, key), RocksDBException);
    ASSERT_THROW(batch.delRange(cf, key1, key2), RocksDBException);
  }
}

TEST_F(native_rocksdb_test, iterator_is_invalid_on_creation) {
  {
    auto it = db->getIterator();
    ASSERT_FALSE(it);
  }

  const auto cf1 = "cf1"s;
  {
    db->createColumnFamily(cf1);
    auto it = db->getIterator(cf1);
    ASSERT_FALSE(it);
  }

  const auto cf2 = "cf2"s;
  {
    db->createColumnFamily(cf2);
    auto iters = db->getIterators({cf1, cf2});
    ASSERT_EQ(iters.size(), 2);
    ASSERT_FALSE(iters[0]);
    ASSERT_FALSE(iters[1]);
  }
}

TEST_F(native_rocksdb_test, iterator_get_throws_for_non_existent_column_families) {
  const auto cf1 = "cf1"s;
  const auto cf2 = "cf2"s;

  ASSERT_THROW(db->getIterator(cf1), RocksDBException);
  ASSERT_THROW(db->getIterators({cf1, cf2}), RocksDBException);
}

TEST_F(native_rocksdb_test, iterate_all_keys_in_default_family) {
  db->put(key1, value1);
  db->put(key2, value2);
  auto it = db->getIterator();
  it.first();
  ASSERT_EQ(it.keyView(), key1);
  ASSERT_EQ(it.valueView(), value1);
  it.next();
  ASSERT_EQ(it.keyView(), key2);
  ASSERT_EQ(it.valueView(), value2);
}

TEST_F(native_rocksdb_test, iterate_all_keys_in_a_family) {
  const auto cf = "cf"s;
  db->createColumnFamily(cf);
  db->put(cf, key1, value1);
  db->put(cf, key2, value2);
  auto it = db->getIterator(cf);
  it.first();
  ASSERT_EQ(it.keyView(), key1);
  ASSERT_EQ(it.valueView(), value1);
  it.next();
  ASSERT_EQ(it.keyView(), key2);
  ASSERT_EQ(it.valueView(), value2);
}

TEST_F(native_rocksdb_test, iterator_going_past_last_is_invalid) {
  const auto cf = "cf"s;
  db->createColumnFamily(cf);
  db->put(key1, value1);
  db->put(cf, key2, value2);

  {
    auto it = db->getIterator();
    it.first();
    ASSERT_NO_THROW(it.next());
    ASSERT_FALSE(it);
  }

  {
    auto it = db->getIterator(cf);
    it.first();
    ASSERT_NO_THROW(it.next());
    ASSERT_FALSE(it);
  }
}

TEST_F(native_rocksdb_test, iterator_going_before_first_is_invalid) {
  const auto cf = "cf"s;
  db->createColumnFamily(cf);
  db->put(key1, value1);
  db->put(cf, key2, value2);

  {
    auto it = db->getIterator();
    it.first();
    ASSERT_NO_THROW(it.prev());
    ASSERT_FALSE(it);
  }

  {
    auto it = db->getIterator(cf);
    it.first();
    ASSERT_NO_THROW(it.prev());
    ASSERT_FALSE(it);
  }
}

TEST_F(native_rocksdb_test, iterator_key_values_and_views_are_equal) {
  const auto cf = "cf"s;
  db->createColumnFamily(cf);
  db->put(key1, value1);
  db->put(cf, key2, value2);

  {
    auto it = db->getIterator();
    it.first();
    ASSERT_EQ(it.key(), key1);
    ASSERT_EQ(it.value(), value1);
    ASSERT_EQ(it.key(), it.keyView());
    ASSERT_EQ(it.value(), it.valueView());
  }

  {
    auto it = db->getIterator(cf);
    it.first();
    ASSERT_EQ(it.key(), key2);
    ASSERT_EQ(it.value(), value2);
    ASSERT_EQ(it.key(), it.keyView());
    ASSERT_EQ(it.value(), it.valueView());
  }
}

TEST_F(native_rocksdb_test, iterator_seek_at_least_in_default_family) {
  db->put(key1, value1);
  db->put(key3, value3);
  auto it = db->getIterator();
  it.seekAtLeast(key2);
  ASSERT_TRUE(it);
  ASSERT_EQ(it.key(), key3);
  ASSERT_EQ(it.value(), value3);
}

TEST_F(native_rocksdb_test, iterator_seek_at_least_in_a_family) {
  const auto cf = "cf"s;
  db->createColumnFamily(cf);
  db->put(cf, key1, value1);
  db->put(cf, key3, value3);
  auto it = db->getIterator(cf);
  it.seekAtLeast(key2);
  ASSERT_TRUE(it);
  ASSERT_EQ(it.key(), key3);
  ASSERT_EQ(it.value(), value3);
}

TEST_F(native_rocksdb_test, iterator_seek_at_most_in_default_family) {
  db->put(key1, value1);
  db->put(key3, value3);
  auto it = db->getIterator();
  it.seekAtMost(key2);
  ASSERT_TRUE(it);
  ASSERT_EQ(it.key(), key1);
  ASSERT_EQ(it.value(), value1);
}

TEST_F(native_rocksdb_test, iterator_seek_at_most_in_a_family) {
  const auto cf = "cf"s;
  db->createColumnFamily(cf);
  db->put(cf, key1, value1);
  db->put(cf, key3, value3);
  auto it = db->getIterator(cf);
  it.seekAtMost(key2);
  ASSERT_TRUE(it);
  ASSERT_EQ(it.key(), key1);
  ASSERT_EQ(it.value(), value1);
}

TEST_F(native_rocksdb_test, iterator_seek_success_after_unsuccessful_seeks) {
  const auto cf = "cf"s;
  db->createColumnFamily(cf);
  db->put(key2, value);
  db->put(cf, key2, value);

  {
    auto it = db->getIterator();
    it.seekAtLeast(key3);
    ASSERT_FALSE(it);

    it.seekAtMost(key1);
    ASSERT_FALSE(it);

    it.seekAtLeast(key2);
    ASSERT_TRUE(it);
  }

  {
    auto it = db->getIterator(cf);
    it.seekAtLeast(key3);
    ASSERT_FALSE(it);

    it.seekAtMost(key1);
    ASSERT_FALSE(it);

    it.seekAtLeast(key2);
    ASSERT_TRUE(it);
  }
}

TEST_F(native_rocksdb_test, iterator_key_value_prev_next_throw_when_invalid) {
  const auto cf = "cf"s;
  db->createColumnFamily(cf);

  {
    auto it = db->getIterator();
    ASSERT_FALSE(it);
    ASSERT_THROW(it.key(), RocksDBException);
    ASSERT_THROW(it.value(), RocksDBException);
    ASSERT_THROW(it.keyView(), RocksDBException);
    ASSERT_THROW(it.valueView(), RocksDBException);
    ASSERT_THROW(it.prev(), RocksDBException);
    ASSERT_THROW(it.next(), RocksDBException);
  }

  {
    auto it = db->getIterator(cf);
    ASSERT_FALSE(it);
    ASSERT_THROW(it.key(), RocksDBException);
    ASSERT_THROW(it.value(), RocksDBException);
    ASSERT_THROW(it.keyView(), RocksDBException);
    ASSERT_THROW(it.valueView(), RocksDBException);
    ASSERT_THROW(it.prev(), RocksDBException);
    ASSERT_THROW(it.next(), RocksDBException);
  }
}

TEST_F(native_rocksdb_test, get_iterators) {
  const auto cf1 = "cf1"s;
  const auto cf2 = "cf2"s;
  db->createColumnFamily(cf1);
  db->createColumnFamily(cf2);
  db->put(cf1, key1, value1);
  db->put(cf2, key2, value2);

  auto iters = db->getIterators({cf1, cf2});

  iters[0].seekAtLeast(key1);
  ASSERT_TRUE(iters[0]);
  ASSERT_EQ(iters[0].key(), key1);
  ASSERT_EQ(iters[0].value(), value1);

  iters[1].seekAtLeast(key2);
  ASSERT_TRUE(iters[1]);
  ASSERT_EQ(iters[1].key(), key2);
  ASSERT_EQ(iters[1].value(), value2);
}

TEST_F(native_rocksdb_test, from_rocksdb_idbclient) {
  db.reset();
  auto idb = TestRocksDb::create();
  auto native = NativeClient::fromIDBClient(idb);

  const auto key1Sliver = Sliver::copy(key1.data(), key1.size());
  const auto key2Sliver = Sliver::copy(key2.data(), key2.size());
  const auto value1Sliver = Sliver::copy(value1.data(), value1.size());
  const auto value2Sliver = Sliver::copy(value2.data(), value2.size());
  idb->put(key1Sliver, value1Sliver);
  native->put(key2, value2);

  ASSERT_EQ(native->get(key1), value1);
  ASSERT_EQ(native->get(key2), value2);

  {
    auto out = Sliver{};
    ASSERT_TRUE(idb->get(key1Sliver, out).isOK());
    ASSERT_EQ(out, value1Sliver);
  }

  {
    auto out = Sliver{};
    ASSERT_TRUE(idb->get(key2Sliver, out).isOK());
    ASSERT_EQ(out, value2Sliver);
  }
}

TEST_F(native_rocksdb_test, from_memorydb_idbclient) {
  auto idb = std::make_shared<memorydb::Client>();
  ASSERT_THROW(NativeClient::fromIDBClient(idb), std::bad_cast);
}

TEST_F(native_rocksdb_test, rocksdb_idbclient_can_open_db_with_families) {
  db.reset();
  auto idb = TestRocksDb::create();
  auto native = NativeClient::fromIDBClient(idb);
  native->createColumnFamily("cf1");
  native->createColumnFamily("cf2");

  idb.reset();
  native.reset();

  idb = TestRocksDb::create();
  native = NativeClient::fromIDBClient(idb);

  ASSERT_THAT(native->columnFamilies(),
              ContainerEq(std::unordered_set<std::string>{native->defaultColumnFamily(), "cf1", "cf2"}));
}

TEST_F(native_rocksdb_test, get_slice_in_default_family) {
  db->put(key, value);
  const auto slice = db->getSlice(key);
  ASSERT_TRUE(slice);
  ASSERT_EQ(*slice, value);
}

TEST_F(native_rocksdb_test, get_slice_in_some_family) {
  const auto cf = "cf"s;
  db->createColumnFamily(cf);
  db->put(cf, key, value);
  const auto slice = db->getSlice(cf, key);
  ASSERT_TRUE(slice);
  ASSERT_EQ(*slice, value);
}

TEST_F(native_rocksdb_test, get_slice_twice_in_default_family) {
  db->put(key, value);
  const auto slice1 = db->getSlice(key);
  const auto slice2 = db->getSlice(key);
  ASSERT_TRUE(slice1);
  ASSERT_EQ(*slice1, value);
  ASSERT_TRUE(slice2);
  ASSERT_EQ(*slice2, value);
}

TEST_F(native_rocksdb_test, get_slice_twice_in_some_family) {
  const auto cf = "cf"s;
  db->createColumnFamily(cf);
  db->put(cf, key, value);
  const auto slice1 = db->getSlice(cf, key);
  const auto slice2 = db->getSlice(cf, key);
  ASSERT_TRUE(slice1);
  ASSERT_EQ(*slice1, value);
  ASSERT_TRUE(slice2);
  ASSERT_EQ(*slice2, value);
}

TEST_F(native_rocksdb_test, get_while_holding_slice_in_default_family) {
  db->put(key, value);
  const auto slice = db->getSlice(key);
  const auto str = db->get(key);
  ASSERT_TRUE(slice);
  ASSERT_EQ(*slice, value);
  ASSERT_TRUE(str);
  ASSERT_EQ(*str, value);
}

TEST_F(native_rocksdb_test, get_while_holding_slice_in_some_family) {
  const auto cf = "cf"s;
  db->createColumnFamily(cf);
  db->put(cf, key, value);
  const auto slice = db->getSlice(cf, key);
  const auto str = db->get(cf, key);
  ASSERT_TRUE(slice);
  ASSERT_EQ(*slice, value);
  ASSERT_TRUE(str);
  ASSERT_EQ(*str, value);
}

TEST_F(native_rocksdb_test, get_non_existent_slice_in_default_family) { ASSERT_FALSE(db->getSlice(key)); }

TEST_F(native_rocksdb_test, get_non_existent_slice_in_some_family) {
  const auto cf = "cf"s;
  db->createColumnFamily(cf);
  ASSERT_FALSE(db->getSlice(cf, key));
}

TEST_F(native_rocksdb_test, multiget_all_keys_exist) {
  const auto cf = "cf"s;
  db->createColumnFamily(cf);
  db->put(cf, key, value);
  db->put(cf, key1, value1);
  db->put(cf, key2, value2);

  std::vector<std::string> keys = {key, key1, key2};
  std::vector<::rocksdb::PinnableSlice> values(keys.size());
  std::vector<::rocksdb::Status> statuses(keys.size());

  db->multiGet(cf, keys, values, statuses);
  ASSERT_EQ(3, statuses.size());
  for (auto &s : statuses) {
    ASSERT_TRUE(s.ok());
  }
  ASSERT_EQ(value, *values[0].GetSelf());
  ASSERT_EQ(value1, *values[1].GetSelf());
  ASSERT_EQ(value2, *values[2].GetSelf());
}

TEST_F(native_rocksdb_test, multiget_one_key_missing) {
  const auto cf = "cf"s;
  db->createColumnFamily(cf);
  db->put(cf, key, value);
  db->put(cf, key2, value2);

  std::vector<std::string> keys = {key, key1, key2};
  std::vector<::rocksdb::PinnableSlice> values(keys.size());
  std::vector<::rocksdb::Status> statuses(keys.size());

  db->multiGet(cf, keys, values, statuses);
  ASSERT_EQ(3, statuses.size());
  ASSERT_TRUE(statuses[0].ok());
  ASSERT_TRUE(statuses[1].IsNotFound());
  ASSERT_TRUE(statuses[2].ok());
  ASSERT_EQ(value, *values[0].GetSelf());
  ASSERT_EQ(value2, *values[2].GetSelf());
}

TEST_F(native_rocksdb_test, multiget_resize_values_and_statuses) {
  const auto cf = "cf"s;
  db->createColumnFamily(cf);
  db->put(cf, key, value);
  db->put(cf, key1, value1);
  db->put(cf, key2, value2);

  std::vector<std::string> keys = {key, key1, key2};
  std::vector<::rocksdb::PinnableSlice> values;
  std::vector<::rocksdb::Status> statuses;
  ASSERT_EQ(0, values.size());
  ASSERT_EQ(0, statuses.size());

  db->multiGet(cf, keys, values, statuses);
  ASSERT_EQ(3, values.size());
  ASSERT_EQ(3, statuses.size());
  for (auto &s : statuses) {
    ASSERT_TRUE(s.ok());
  }
  ASSERT_EQ(value, *values[0].GetSelf());
  ASSERT_EQ(value1, *values[1].GetSelf());
  ASSERT_EQ(value2, *values[2].GetSelf());
}

TEST_F(native_rocksdb_test, create_rocksdb_checkpoint) {
  auto checkPointDirPath = db->path() + "_checkpoint";
  db->setCheckpointDirNative(checkPointDirPath);
  auto batch = db->getBatch();
  batch.put(key1, value1);
  batch.put(key2, value2);
  db->write(std::move(batch));
  auto dbValue1 = db->get(key1);
  auto dbValue2 = db->get(key2);
  ASSERT_TRUE(dbValue1.has_value());
  ASSERT_EQ(*dbValue1, value1);
  ASSERT_TRUE(dbValue2.has_value());
  ASSERT_EQ(*dbValue2, value2);
  db->createCheckpointNative(1);
  auto checkPoints = db->getListOfCreatedCheckpointsNative();
  ASSERT_EQ(checkPoints.size(), 1);
  db->createCheckpointNative(2);
  checkPoints = db->getListOfCreatedCheckpointsNative();
  ASSERT_EQ(checkPoints.size(), 2);
  ASSERT_TRUE(dbValue1.has_value());
  ASSERT_EQ(*dbValue1, value1);
  ASSERT_TRUE(dbValue2.has_value());
  ASSERT_EQ(*dbValue2, value2);
  db->removeCheckpointNative(2);
  checkPoints = db->getListOfCreatedCheckpointsNative();
  ASSERT_EQ(checkPoints.size(), 1);
  db->removeCheckpointNative(1);
  checkPoints = db->getListOfCreatedCheckpointsNative();
  ASSERT_EQ(checkPoints.size(), 0);
}

TEST_F(native_rocksdb_test, create_rocksdb_checkpoint_and_update_db) {
  auto checkPointDirPath = db->path() + "_checkpoint";
  db->setCheckpointDirNative(checkPointDirPath);
  db->put(key, value);
  auto dbValue = db->get(key);
  ASSERT_TRUE(dbValue.has_value());
  ASSERT_EQ(*dbValue, value);
  db->createCheckpointNative(1);
  auto checkPoints = db->getListOfCreatedCheckpointsNative();
  ASSERT_EQ(checkPoints.size(), 1);
  dbValue = db->get(key);
  ASSERT_TRUE(dbValue.has_value());
  ASSERT_EQ(*dbValue, value);
  db->put(key1, value1);
  auto dbValue1 = db->get(key1);
  ASSERT_TRUE(dbValue1.has_value());
  ASSERT_EQ(*dbValue1, value1);
  dbValue = db->get(key);
  ASSERT_TRUE(dbValue.has_value());
  ASSERT_EQ(*dbValue, value);
  db->removeCheckpointNative(1);
  checkPoints = db->getListOfCreatedCheckpointsNative();
  ASSERT_EQ(checkPoints.size(), 0);
}

TEST_F(native_rocksdb_test, create_checkpoint_and_verify_its_content) {
  auto checkPointDirPath = db->path() + "_checkpoint";
  db->setCheckpointDirNative(checkPointDirPath);

  // inserting key, value in db
  db->put(key, value);
  auto dbValue = db->get(key);
  ASSERT_TRUE(dbValue.has_value());
  ASSERT_EQ(*dbValue, value);

  // creating checkpoint 1
  db->createCheckpointNative(1);
  auto checkPoints = db->getListOfCreatedCheckpointsNative();
  ASSERT_EQ(checkPoints.size(), 1);

  // dbSnapshot path where checkpoint 1 is created
  std::string cpPath = checkPointDirPath + "/" + std::to_string(checkPoints.back());
  getSnapshotDb(cpPath);

  // verifying that checkpoint 1 have key and specific value which is stored in original db.
  auto dbSnapshotValue = snapshotDb->get(key);
  ASSERT_TRUE(dbSnapshotValue.has_value());
  ASSERT_EQ(*dbSnapshotValue, value);

  // inserting key1, value1 in db
  db->put(key1, value1);
  dbValue = db->get(key1);
  ASSERT_TRUE(dbValue.has_value());
  ASSERT_EQ(*dbValue, value1);

  // verifying that key1 and specific value1 is not stored in checkpoint 1
  dbSnapshotValue = snapshotDb->get(key1);
  ASSERT_FALSE(dbSnapshotValue.has_value());
  ASSERT_NE(*dbSnapshotValue, value1);

  db->removeCheckpointNative(1);
  checkPoints = db->getListOfCreatedCheckpointsNative();
  ASSERT_EQ(checkPoints.size(), 0);
}

TEST_F(native_rocksdb_test, create_rocksdb_checkpoint_and_update_db_and_verify_with_snapshot) {
  auto checkPointDirPath = db->path() + "_checkpoint";
  db->setCheckpointDirNative(checkPointDirPath);
  const std::string key{"key"};
  const std::string value{"value"};
  const std::string value1{"value1"};

  // inserting key, value in db
  db->put(key, value);
  auto dbValue = db->get(key);
  ASSERT_TRUE(dbValue.has_value());
  ASSERT_EQ(*dbValue, value);

  // creating checkpoint
  db->createCheckpointNative(1);
  auto checkPoints = db->getListOfCreatedCheckpointsNative();
  ASSERT_EQ(checkPoints.size(), 1);

  std::string cpPath = checkPointDirPath + "/" + std::to_string(checkPoints.back());
  getSnapshotDb(cpPath);
  auto dbSnapshotValue = snapshotDb->get(key);
  ASSERT_TRUE(dbSnapshotValue.has_value());
  ASSERT_EQ(*dbSnapshotValue, value);

  // update existing key in db
  db->put(key, value1);
  dbValue = db->get(key);
  ASSERT_TRUE(dbValue.has_value());
  ASSERT_EQ(*dbValue, value1);

  // values are not same in db and snapshot db
  dbSnapshotValue = snapshotDb->get(key);
  ASSERT_NE(*dbSnapshotValue, dbValue);

  db->removeCheckpointNative(1);
  checkPoints = db->getListOfCreatedCheckpointsNative();
  ASSERT_EQ(checkPoints.size(), 0);
}

TEST_F(native_rocksdb_test, restore_db_from_snapshot) {
  auto checkPointDirPath = db->path() + "_checkpoint";
  db->setCheckpointDirNative(checkPointDirPath);

  // inserting key, value in db
  db->put(key, value);
  auto dbValue = db->get(key);
  ASSERT_TRUE(dbValue.has_value());
  ASSERT_EQ(*dbValue, value);

  // creating checkpoint 5
  db->createCheckpointNative(5);
  auto checkPoints = db->getListOfCreatedCheckpointsNative();
  ASSERT_EQ(checkPoints.size(), 1);

  // destroying the original db
  db.reset();
  ASSERT_EQ(0, db.use_count());
  cleanup();

  // restore from checkpoint
  std::string cpPath = checkPointDirPath + "/" + std::to_string(checkPoints.back());
  db = TestRocksDbSnapshot::createNative(cpPath);

  // verifying that restore db have key and specific value which is stored in original db.
  auto dbSnapshotValue = db->get(key);
  ASSERT_TRUE(dbSnapshotValue.has_value());
  ASSERT_EQ(*dbSnapshotValue, value);

  // verifying there is no checkpoint is created
  checkPoints = db->getListOfCreatedCheckpointsNative();
  ASSERT_EQ(checkPoints.size(), 0);
}

//////TIMESTAMP SUPPORT/////////

template <typename... Sliceable>
auto getSliceArray(const Sliceable &... sls) {
  return std::array<::rocksdb::Slice, sizeof...(sls)>{sls...};
}

TEST_F(native_rocksdb_test, put_and_get_with_timestamp_basic) {
  const auto cf = "cf"s;
  auto cf_options = ::rocksdb::ColumnFamilyOptions{};
  cf_options.comparator = concord::storage::rocksdb::getLexicographic64TsComparator();
  db->createColumnFamily(cf, cf_options);

  uint64_t timestamp = 420;
  auto tsStr = concordUtils::toBigEndianStringBuffer(timestamp);
  std::string key = "time";
  std::string value = "val";
  db->put(cf, key, tsStr, value);

  std::string outTs;
  auto val = db->get(cf, key, tsStr, &outTs);
  ASSERT_TRUE(val.has_value());
  ASSERT_EQ(*val, value);
  ASSERT_EQ(outTs, tsStr);
  auto ioutTs = concordUtils::fromBigEndianBuffer<uint64_t>(outTs.data());
  ASSERT_EQ(timestamp, ioutTs);
}

TEST_F(native_rocksdb_test, put_and_get_with_timestamp_adv) {
  const auto cf = "cf"s;
  auto cf_options = ::rocksdb::ColumnFamilyOptions{};
  cf_options.comparator = concord::storage::rocksdb::getLexicographic64TsComparator();
  db->createColumnFamily(cf, cf_options);

  uint64_t timestamp = 420;
  auto tsStr = concordUtils::toBigEndianStringBuffer(timestamp);
  std::string key = "time";
  std::string value = "val";
  db->put(cf, key, tsStr, value);

  // Try to get with lower timestamp
  std::string outTs;
  uint64_t lowerTimestamp = 419;
  auto lowtsStr = concordUtils::toBigEndianStringBuffer(lowerTimestamp);
  auto val = db->get(cf, key, lowtsStr, &outTs);
  ASSERT_FALSE(val.has_value());

  // Get with higer
  uint64_t highrTimestamp = 425;
  auto highsStr = concordUtils::toBigEndianStringBuffer(highrTimestamp);
  val = db->get(cf, key, highsStr, &outTs);
  ASSERT_TRUE(val.has_value());
  ASSERT_EQ(*val, value);
  // Should return 420
  ASSERT_EQ(outTs, tsStr);
  auto ioutTs = concordUtils::fromBigEndianBuffer<uint64_t>(outTs.data());
  ASSERT_EQ(timestamp, ioutTs);
}

TEST_F(native_rocksdb_test, put_and_get_multiple_timestamps) {
  const auto cf = "cf"s;
  auto cf_options = ::rocksdb::ColumnFamilyOptions{};
  cf_options.comparator = concord::storage::rocksdb::getLexicographic64TsComparator();
  db->createColumnFamily(cf, cf_options);

  uint64_t timestamp = 420;
  auto tsStr = concordUtils::toBigEndianStringBuffer(timestamp);
  std::string key = "time";
  std::string value = "val";
  db->put(cf, key, tsStr, value);

  uint64_t timestamp2 = 430;
  auto tsStr2 = concordUtils::toBigEndianStringBuffer(timestamp2);
  std::string value2 = "val2";
  db->put(cf, key, tsStr2, value2);

  // Try to get with lower timestamp
  std::string outTs;
  uint64_t lowerTimestamp = 419;
  auto lowtsStr = concordUtils::toBigEndianStringBuffer(lowerTimestamp);
  auto val = db->get(cf, key, lowtsStr, &outTs);
  ASSERT_FALSE(val.has_value());

  uint64_t firstTs = 420;
  auto ftsStr = concordUtils::toBigEndianStringBuffer(firstTs);
  val = db->get(cf, key, ftsStr, &outTs);
  ASSERT_TRUE(val.has_value());
  ASSERT_EQ(*val, value);
  // Should return 420
  ASSERT_EQ(outTs, tsStr);
  auto ioutTs = concordUtils::fromBigEndianBuffer<uint64_t>(outTs.data());
  ASSERT_EQ(timestamp, ioutTs);

  // in between shouold return 420
  uint64_t midTs = 424;
  auto mtsStr = concordUtils::toBigEndianStringBuffer(midTs);
  val = db->get(cf, key, mtsStr, &outTs);
  ASSERT_TRUE(val.has_value());
  ASSERT_EQ(*val, value);
  // Should return 420
  ASSERT_EQ(outTs, tsStr);
  ioutTs = concordUtils::fromBigEndianBuffer<uint64_t>(outTs.data());
  ASSERT_EQ(timestamp, ioutTs);

  // second return 430
  uint64_t hTs = 430;
  auto htsStr = concordUtils::toBigEndianStringBuffer(hTs);
  val = db->get(cf, key, htsStr, &outTs);
  ASSERT_TRUE(val.has_value());
  ASSERT_EQ(*val, value2);
  ASSERT_EQ(outTs, tsStr2);
  ioutTs = concordUtils::fromBigEndianBuffer<uint64_t>(outTs.data());
  ASSERT_EQ(timestamp2, ioutTs);

  // higher return 430
  uint64_t hTs2 = 43000;
  auto htsStr2 = concordUtils::toBigEndianStringBuffer(hTs2);
  val = db->get(cf, key, htsStr2, &outTs);
  ASSERT_TRUE(val.has_value());
  ASSERT_EQ(*val, value2);
  ASSERT_EQ(outTs, tsStr2);
  ioutTs = concordUtils::fromBigEndianBuffer<uint64_t>(outTs.data());
  ASSERT_EQ(timestamp2, ioutTs);
}

TEST_F(native_rocksdb_test, delete_with_timestamp) {
  const auto cf = "cf"s;
  auto cf_options = ::rocksdb::ColumnFamilyOptions{};
  cf_options.comparator = concord::storage::rocksdb::getLexicographic64TsComparator();
  db->createColumnFamily(cf, cf_options);

  uint64_t timestamp = 420;
  auto tsStr = concordUtils::toBigEndianStringBuffer(timestamp);
  std::string key = "time";
  std::string value = "val";
  db->put(cf, key, tsStr, value);

  // try to delete with lower timestamp
  uint64_t lowerTimestamp = 400;
  auto lowerTsStr = concordUtils::toBigEndianStringBuffer(lowerTimestamp);
  db->del(cf, key, lowerTsStr);

  // get the value of 420
  {
    std::string outTs;
    auto val = db->get(cf, key, tsStr, &outTs);
    ASSERT_TRUE(val.has_value());
    ASSERT_EQ(*val, value);
    ASSERT_EQ(outTs, tsStr);
    auto ioutTs = concordUtils::fromBigEndianBuffer<uint64_t>(outTs.data());
    ASSERT_EQ(timestamp, ioutTs);
  }

  // delete with higher ts
  uint64_t higherTimestamp = 500;
  auto higherTsStr = concordUtils::toBigEndianStringBuffer(higherTimestamp);
  db->del(cf, key, higherTsStr);

  // get the value at 500
  {
    std::string outTs;
    auto val = db->get(cf, key, higherTsStr, &outTs);
    ASSERT_FALSE(val.has_value());
  }

  // get the value of 420
  {
    std::string outTs;
    auto val = db->get(cf, key, tsStr, &outTs);
    ASSERT_TRUE(val.has_value());
    ASSERT_EQ(*val, value);
    ASSERT_EQ(outTs, tsStr);
    auto ioutTs = concordUtils::fromBigEndianBuffer<uint64_t>(outTs.data());
    ASSERT_EQ(timestamp, ioutTs);
  }

  // try to delete with ts
  db->del(cf, key, tsStr);

  // get the value of 420
  {
    std::string outTs;
    auto val = db->get(cf, key, tsStr, &outTs);
    ASSERT_FALSE(val.has_value());
  }
}

TEST_F(native_rocksdb_test, put_in_batch_with_timestamps) {
  const auto cf1 = "cf1"s;
  auto cf_options = ::rocksdb::ColumnFamilyOptions{};
  cf_options.comparator = concord::storage::rocksdb::getLexicographic64TsComparator();
  db->createColumnFamily(cf1, cf_options);
  auto batch = db->getBatch();

  uint64_t timestamp = 420;
  auto tsStr = concordUtils::toBigEndianStringBuffer(timestamp);
  std::string key = "time";
  std::string value = "val";
  auto key1_ts = getSliceArray(key, tsStr);
  auto sl_val = getSliceArray(value);

  std::string key2 = "time2";
  std::string value2 = "val2";
  auto key2_ts = getSliceArray(key2, tsStr);
  auto sl_val2 = getSliceArray(value2);

  batch.put(cf1, key1_ts, sl_val);
  batch.put(cf1, key2_ts, sl_val2);
  db->write(std::move(batch));

  // try to read with lower timestamp
  uint64_t lowerTimestamp = 400;
  auto lowerTsStr = concordUtils::toBigEndianStringBuffer(lowerTimestamp);

  {
    std::string outTs;
    auto val = db->get(cf1, key, lowerTsStr, &outTs);
    ASSERT_FALSE(val.has_value());
    val = db->get(cf1, key2, lowerTsStr, &outTs);
    ASSERT_FALSE(val.has_value());
  }

  {
    // try to read with higher timestamp
    uint64_t higherTimestamp = 500;
    auto highTsStr = concordUtils::toBigEndianStringBuffer(higherTimestamp);
    std::string outTs;
    auto val = db->get(cf1, key, highTsStr, &outTs);
    ASSERT_TRUE(val.has_value());
    ASSERT_EQ(*val, value);
    ASSERT_EQ(outTs, tsStr);
    auto ioutTs = concordUtils::fromBigEndianBuffer<uint64_t>(outTs.data());
    ASSERT_EQ(timestamp, ioutTs);
  }
}

TEST_F(native_rocksdb_test, 2cf_one_with_timestamp) {
  const auto cf1 = "cf1"s;
  auto cf_options = ::rocksdb::ColumnFamilyOptions{};
  cf_options.comparator = concord::storage::rocksdb::getLexicographic64TsComparator();
  db->createColumnFamily(cf1, cf_options);
  const auto cf2 = "cf2"s;
  db->createColumnFamily(cf2);
  auto batch = db->getBatch();

  uint64_t timestamp = 420;
  auto tsStr = concordUtils::toBigEndianStringBuffer(timestamp);
  std::string key = "time";
  std::string value = "val";

  std::string key2 = "time2";
  std::string value2 = "val2";

  batch.put(cf1, getSliceArray(key, tsStr), getSliceArray(value));
  batch.put(cf2, key2, value2);
  db->write(std::move(batch));

  {
    // read with timestamp
    std::string outTs;
    auto val = db->get(cf1, key, tsStr, &outTs);
    ASSERT_TRUE(val.has_value());
    ASSERT_EQ(*val, value);
    ASSERT_EQ(outTs, tsStr);
    auto ioutTs = concordUtils::fromBigEndianBuffer<uint64_t>(outTs.data());
    ASSERT_EQ(timestamp, ioutTs);
  }
  {
    // read with without timestamp
    auto val = db->get(cf2, key2);
    ASSERT_TRUE(val.has_value());
    ASSERT_EQ(*val, value2);
  }
}

TEST_F(native_rocksdb_test, multi_part_write) {
  const auto cf1 = "cf1"s;
  auto cf_options = ::rocksdb::ColumnFamilyOptions{};
  cf_options.comparator = concord::storage::rocksdb::getLexicographic64TsComparator();
  db->createColumnFamily(cf1, cf_options);

  auto batch = db->getBatch();
  uint64_t timestamp = 420;
  auto tsStr = concordUtils::toBigEndianStringBuffer(timestamp);
  std::string key = "time";
  std::string value = "val";

  std::string prefix = ".";
  std::string key2 = "time2";
  std::string value2 = "val2";

  std::string key_with_prefix = prefix + key2;

  batch.put(cf1, getSliceArray(key, tsStr), getSliceArray(value));
  batch.put(cf1, getSliceArray(prefix, key2, tsStr), getSliceArray(value2));
  db->write(std::move(batch));

  {
    std::string outTs;
    auto val = db->get(cf1, key, tsStr, &outTs);
    ASSERT_TRUE(val.has_value());
    ASSERT_EQ(*val, value);
    ASSERT_EQ(outTs, tsStr);
    auto ioutTs = concordUtils::fromBigEndianBuffer<uint64_t>(outTs.data());
    ASSERT_EQ(timestamp, ioutTs);

    auto val2 = db->get(cf1, key_with_prefix, tsStr, &outTs);
    ASSERT_TRUE(val2.has_value());
    ASSERT_EQ(*val2, value2);
    ASSERT_EQ(outTs, tsStr);
    ioutTs = concordUtils::fromBigEndianBuffer<uint64_t>(outTs.data());
    ASSERT_EQ(timestamp, ioutTs);

    // Without the prefix
    val2 = db->get(cf1, key2, tsStr, &outTs);
    ASSERT_FALSE(val2.has_value());
    val2 = db->get(cf1, prefix, tsStr, &outTs);
    ASSERT_FALSE(val2.has_value());
  }
}

TEST_F(native_rocksdb_test, write_batch_with_Delete) {
  const auto cf1 = "cf1"s;
  auto cf_options = ::rocksdb::ColumnFamilyOptions{};
  cf_options.comparator = concord::storage::rocksdb::getLexicographic64TsComparator();
  db->createColumnFamily(cf1, cf_options);

  uint64_t timestamp = 420;
  auto tsStr = concordUtils::toBigEndianStringBuffer(timestamp);
  std::string key = "time";
  std::string value = "val";

  std::string key2 = "time2";
  std::string value2 = "val2";

  {
    auto batch = db->getBatch();
    batch.put(cf1, getSliceArray(key, tsStr), getSliceArray(value));
    batch.put(cf1, getSliceArray(key2, tsStr), getSliceArray(value2));
    db->write(std::move(batch));
  }

  {
    // read with timestamp
    std::string outTs;
    auto val = db->get(cf1, key, tsStr, &outTs);
    ASSERT_TRUE(val.has_value());
    ASSERT_EQ(*val, value);
    ASSERT_EQ(outTs, tsStr);
    auto ioutTs = concordUtils::fromBigEndianBuffer<uint64_t>(outTs.data());
    ASSERT_EQ(timestamp, ioutTs);
  }

  std::string value3 = "val3";
  std::string value4 = "val4";

  uint64_t timestamp2 = 422;
  auto tsStr2 = concordUtils::toBigEndianStringBuffer(timestamp2);
  {
    auto batch = db->getBatch();
    batch.put(cf1, getSliceArray(key2, tsStr2), getSliceArray(value4));
    batch.del(cf1, getSliceArray(key, tsStr2));
    db->write(std::move(batch));
  }

  //// key #1
  {
    // read with higher timestamp deleted value at 422
    uint64_t higer_timestamp = 423;
    auto higher_ts_str = concordUtils::toBigEndianStringBuffer(higer_timestamp);
    std::string outTs;
    auto val = db->get(cf1, key, higher_ts_str, &outTs);
    ASSERT_FALSE(val.has_value());
  }

  {
    // read with deletion timestamp deleted value at 422
    std::string outTs;
    auto val = db->get(cf1, key, tsStr2, &outTs);
    ASSERT_FALSE(val.has_value());
  }

  {
    // read with timestamp 420
    std::string outTs;
    auto val = db->get(cf1, key, tsStr, &outTs);
    ASSERT_TRUE(val.has_value());
    ASSERT_EQ(*val, value);
    ASSERT_EQ(outTs, tsStr);
    auto ioutTs = concordUtils::fromBigEndianBuffer<uint64_t>(outTs.data());
    ASSERT_EQ(timestamp, ioutTs);
  }

  //// key #2

  {
    // read with timestamp 420
    std::string outTs;
    auto val = db->get(cf1, key2, tsStr, &outTs);
    ASSERT_TRUE(val.has_value());
    ASSERT_EQ(*val, value2);
    ASSERT_EQ(outTs, tsStr);
    auto ioutTs = concordUtils::fromBigEndianBuffer<uint64_t>(outTs.data());
    ASSERT_EQ(timestamp, ioutTs);
  }

  {
    // read with timestamp 421
    std::string outTs;
    auto val = db->get(cf1, key2, tsStr2, &outTs);
    ASSERT_TRUE(val.has_value());
    ASSERT_EQ(*val, value4);
    ASSERT_EQ(outTs, tsStr2);
    auto ioutTs = concordUtils::fromBigEndianBuffer<uint64_t>(outTs.data());
    ASSERT_EQ(timestamp2, ioutTs);
  }
}

TEST_F(native_rocksdb_test, write_delete_update) {
  const auto cf1 = "cf1"s;
  auto cf_options = ::rocksdb::ColumnFamilyOptions{};
  cf_options.comparator = concord::storage::rocksdb::getLexicographic64TsComparator();
  db->createColumnFamily(cf1, cf_options);

  uint64_t timestamp = 420;
  auto tsStr = concordUtils::toBigEndianStringBuffer(timestamp);
  std::string key = "time";
  std::string value = "val";

  {
    auto batch = db->getBatch();
    batch.put(cf1, getSliceArray(key, tsStr), getSliceArray(value));
    db->write(std::move(batch));
  }

  {
    // read with timestamp
    std::string outTs;
    auto val = db->get(cf1, key, tsStr, &outTs);
    ASSERT_TRUE(val.has_value());
    ASSERT_EQ(*val, value);
    ASSERT_EQ(outTs, tsStr);
    auto ioutTs = concordUtils::fromBigEndianBuffer<uint64_t>(outTs.data());
    ASSERT_EQ(timestamp, ioutTs);
  }
  // UPdate
  uint64_t timestamp2 = 422;
  auto tsStr2 = concordUtils::toBigEndianStringBuffer(timestamp2);
  std::string value2 = "val2";
  {
    auto batch = db->getBatch();
    batch.put(cf1, getSliceArray(key, tsStr2), getSliceArray(value2));
    db->write(std::move(batch));
  }
  {
    // read with timestamp
    std::string outTs;
    auto val = db->get(cf1, key, tsStr2, &outTs);
    ASSERT_TRUE(val.has_value());
    ASSERT_EQ(*val, value2);
    ASSERT_EQ(outTs, tsStr2);
    auto ioutTs = concordUtils::fromBigEndianBuffer<uint64_t>(outTs.data());
    ASSERT_EQ(timestamp2, ioutTs);
  }

  // Delete with timestamp2
  {
    auto batch = db->getBatch();
    batch.del(cf1, getSliceArray(key, tsStr2));
    db->write(std::move(batch));
  }

  {
    // read with deletion timestamp deleted value at 422
    std::string outTs;
    auto val = db->get(cf1, key, tsStr2, &outTs);
    ASSERT_FALSE(val.has_value());
  }
  // update again
  {
    auto batch = db->getBatch();
    batch.put(cf1, getSliceArray(key, tsStr2), getSliceArray(value2));
    db->write(std::move(batch));
  }
  {
    // read with timestamp
    std::string outTs;
    auto val = db->get(cf1, key, tsStr2, &outTs);
    ASSERT_TRUE(val.has_value());
    ASSERT_EQ(*val, value2);
    ASSERT_EQ(outTs, tsStr2);
    auto ioutTs = concordUtils::fromBigEndianBuffer<uint64_t>(outTs.data());
    ASSERT_EQ(timestamp2, ioutTs);
  }
}

TEST_F(native_rocksdb_test, lexicographic_timestamp_comparator) {
  auto comparator = concord::storage::rocksdb::getLexicographic64TsComparator();

  // First is less than second
  {
    uint64_t timestamp = 420;
    auto ts1 = concordUtils::toBigEndianStringBuffer(timestamp);
    uint64_t timestamp2 = 421;
    auto ts2 = concordUtils::toBigEndianStringBuffer(timestamp2);
    auto slTs1 = detail::toSlice(ts1);
    auto slTs2 = detail::toSlice(ts2);
    auto comp = comparator->CompareTimestamp(slTs1, slTs2);
    ASSERT_EQ(comp, -1);
  }

  // First is larger than second
  {
    uint64_t timestamp = 422;
    auto ts1 = concordUtils::toBigEndianStringBuffer(timestamp);
    uint64_t timestamp2 = 421;
    auto ts2 = concordUtils::toBigEndianStringBuffer(timestamp2);
    auto slTs1 = detail::toSlice(ts1);
    auto slTs2 = detail::toSlice(ts2);
    auto comp = comparator->CompareTimestamp(slTs1, slTs2);
    ASSERT_EQ(comp, 1);
  }

  // equal
  {
    uint64_t timestamp = 420;
    auto ts1 = concordUtils::toBigEndianStringBuffer(timestamp);
    uint64_t timestamp2 = 420;
    auto ts2 = concordUtils::toBigEndianStringBuffer(timestamp2);
    auto slTs1 = detail::toSlice(ts1);
    auto slTs2 = detail::toSlice(ts2);
    auto comp = comparator->CompareTimestamp(slTs1, slTs2);
    ASSERT_EQ(comp, 0);
  }
}

TEST_F(native_rocksdb_test, remove_history_on_compaction) {
  const auto cf1 = "cf1"s;
  auto cf_options = ::rocksdb::ColumnFamilyOptions{};
  cf_options.comparator = concord::storage::rocksdb::getLexicographic64TsComparator();
  db->createColumnFamily(cf1, cf_options);
  std::string key = "time";
  std::string key2 = "time100";
  std::string value1 = "val1";
  std::string value2 = "val2";
  uint64_t timestamp1 = 420;
  uint64_t timestamp2 = 450;

  {
    auto tsStr = concordUtils::toBigEndianStringBuffer(timestamp1);
    auto batch = db->getBatch();
    batch.put(cf1, getSliceArray(key, tsStr), getSliceArray(value1));
    db->write(std::move(batch));
  }
  // update
  {
    auto tsStr = concordUtils::toBigEndianStringBuffer(timestamp2);
    auto batch = db->getBatch();
    batch.put(cf1, getSliceArray(key, tsStr), getSliceArray(value2));
    db->write(std::move(batch));
  }

  {
    // read with timestamp 420
    auto tsStr = concordUtils::toBigEndianStringBuffer(timestamp1);
    std::string outTs;
    auto val = db->get(cf1, key, tsStr, &outTs);
    ASSERT_TRUE(val.has_value());
    ASSERT_EQ(*val, value1);
    ASSERT_EQ(outTs, tsStr);
    auto ioutTs = concordUtils::fromBigEndianBuffer<uint64_t>(outTs.data());
    ASSERT_EQ(timestamp1, ioutTs);
  }

  {
    // read with timestamp 450
    auto tsStr = concordUtils::toBigEndianStringBuffer(timestamp2);
    std::string outTs;
    auto val = db->get(cf1, key, tsStr, &outTs);
    ASSERT_TRUE(val.has_value());
    ASSERT_EQ(*val, value2);
    ASSERT_EQ(outTs, tsStr);
    auto ioutTs = concordUtils::fromBigEndianBuffer<uint64_t>(outTs.data());
    ASSERT_EQ(timestamp2, ioutTs);
  }

  // set low time stamp to 451
  uint64_t threshold1 = 451;
  auto threshold1_str = concordUtils::toBigEndianStringBuffer(threshold1);
  auto &raw_db = db->rawDB();
  // raw_db.IncreaseFullHistoryTsLow(db->columnFamilyHandle(cf1), threshold1_str);
  ::rocksdb::Slice begin(key);
  ::rocksdb::Slice end(key2);
  ::rocksdb::Slice ts_low(threshold1_str);
  ::rocksdb::CompactRangeOptions options;
  options.full_history_ts_low = &ts_low;
  auto s = raw_db.CompactRange(options, db->columnFamilyHandle(cf1), nullptr, nullptr);
  auto status = s.ToString();
  ASSERT_EQ(status, "OK");

  {
    // read with timestamp 420
    auto tsStr = concordUtils::toBigEndianStringBuffer(timestamp1);
    std::string outTs;
    auto val = db->get(cf1, key, tsStr, &outTs);
    ASSERT_FALSE(val.has_value());
  }

  {
    // read with timestamp 450 -- latest
    auto tsStr = concordUtils::toBigEndianStringBuffer(timestamp2);
    std::string outTs;
    auto val = db->get(cf1, key, tsStr, &outTs);
    ASSERT_TRUE(val.has_value());
    ASSERT_EQ(*val, value2);
    ASSERT_EQ(outTs, tsStr);
    auto ioutTs = concordUtils::fromBigEndianBuffer<uint64_t>(outTs.data());
    ASSERT_EQ(timestamp2, ioutTs);
  }
}

TEST_F(native_rocksdb_test, remove_history_on_compaction_with_delete) {
  const auto cf1 = "cf1"s;
  auto cf_options = ::rocksdb::ColumnFamilyOptions{};
  cf_options.comparator = concord::storage::rocksdb::getLexicographic64TsComparator();
  db->createColumnFamily(cf1, cf_options);
  std::string key = "time";
  std::string key2 = "time100";
  std::string value1 = "val1";
  std::string value2 = "val2";
  uint64_t timestamp1 = 420;
  uint64_t timestamp2 = 450;

  {
    auto tsStr = concordUtils::toBigEndianStringBuffer(timestamp1);
    auto batch = db->getBatch();
    batch.put(cf1, getSliceArray(key, tsStr), getSliceArray(value1));
    db->write(std::move(batch));
  }
  // delete
  {
    auto tsStr = concordUtils::toBigEndianStringBuffer(timestamp2);
    auto batch = db->getBatch();
    batch.del(cf1, getSliceArray(key, tsStr));
    db->write(std::move(batch));
  }

  {
    // read with timestamp 420
    auto tsStr = concordUtils::toBigEndianStringBuffer(timestamp1);
    std::string outTs;
    auto val = db->get(cf1, key, tsStr, &outTs);
    ASSERT_TRUE(val.has_value());
    ASSERT_EQ(*val, value1);
    ASSERT_EQ(outTs, tsStr);
    auto ioutTs = concordUtils::fromBigEndianBuffer<uint64_t>(outTs.data());
    ASSERT_EQ(timestamp1, ioutTs);
  }

  {
    // read with timestamp 450
    auto tsStr = concordUtils::toBigEndianStringBuffer(timestamp2);
    std::string outTs;
    auto val = db->get(cf1, key, tsStr, &outTs);
    ASSERT_FALSE(val.has_value());
  }

  // set low time stamp to 451
  uint64_t threshold1 = 451;
  auto threshold1_str = concordUtils::toBigEndianStringBuffer(threshold1);
  auto &raw_db = db->rawDB();
  // raw_db.IncreaseFullHistoryTsLow(db->columnFamilyHandle(cf1), threshold1_str);
  ::rocksdb::Slice begin(key);
  ::rocksdb::Slice end(key2);
  ::rocksdb::Slice ts_low(threshold1_str);
  ::rocksdb::CompactRangeOptions options;
  options.full_history_ts_low = &ts_low;
  auto s = raw_db.CompactRange(options, db->columnFamilyHandle(cf1), nullptr, nullptr);
  auto status = s.ToString();
  ASSERT_EQ(status, "OK");

  {
    // read with timestamp 420
    auto tsStr = concordUtils::toBigEndianStringBuffer(timestamp1);
    std::string outTs;
    auto val = db->get(cf1, key, tsStr, &outTs);
    ASSERT_FALSE(val.has_value());
  }

  {
    // read with timestamp 450 -- latest
    auto tsStr = concordUtils::toBigEndianStringBuffer(timestamp2);
    std::string outTs;
    auto val = db->get(cf1, key, tsStr, &outTs);
    ASSERT_FALSE(val.has_value());
  }
}

}  // namespace

int main(int argc, char *argv[]) {
  ::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
