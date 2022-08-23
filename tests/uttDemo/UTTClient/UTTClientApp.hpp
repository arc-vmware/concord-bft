// Concord
//
// Copyright (c) 2018-2022 VMware, Inc. All Rights Reserved.
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

#include <sstream>
#include <queue>

#include "Logger.hpp"
#include "utt_blockchain_app.hpp"

/////////////////////////////////////////////////////////////////////////////////////////////////////
class UTTClientApp : public UTTBlockchainApp {
 public:
  UTTClientApp(logging::Logger& logger, uint16_t walletId);

  uint16_t getNumReplicas() const { return numReplicas_; }
  uint16_t getSigThresh() const { return sigThresh_; }

  const std::string& getMyPid() const;
  const Account& getMyAccount() const;

  const libutt::Wallet& getMyUttWallet() const;
  const std::set<std::string>& getOtherPids() const;

  size_t getUttBalance() const;
  size_t getUttBudget() const;

  template <typename T>
  std::string fmtCurrency(T val) const {
    return "$" + std::to_string(val);
  }

 private:
  void executeTx(const Tx& tx) override;
  void pruneSpentCoins();
  void tryClaimCoins(const TxUtt& tx);

  logging::Logger& logger_;
  std::string myPid_;
  std::set<std::string> otherPids_;
  libutt::Wallet wallet_;

  // [TODO-UTT] Check these assumptions when loading a config
  uint16_t numReplicas_ = 4;
  uint16_t sigThresh_ = 2;  // F + 1
};