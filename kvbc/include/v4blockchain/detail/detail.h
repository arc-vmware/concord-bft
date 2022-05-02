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

#pragma once
#include <chrono>

namespace concord::kvbc::v4blockchain::detail {
using version_type = uint16_t;
enum class block_version : version_type { V1 = 0x1 };
struct ScopedDuration {
  ScopedDuration(const char* msg) : msg_(msg) {}
  ~ScopedDuration() {
    auto jobDuration =
        std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - start).count();
    LOG_INFO(V4_BLOCK_LOG, msg_ << " duration [" << jobDuration << "] micro");
  }
  const char* msg_;
  const std::chrono::time_point<std::chrono::steady_clock> start = std::chrono::steady_clock::now();
};

}  // namespace concord::kvbc::v4blockchain::detail