// Concord
//
// Copyright (c) 2022 VMware, Inc. All Rights Reserved.
//
// This product is licensed to you under the Apache 2.0 license (the "License").
// You may not use this product except in compliance with the Apache 2.0
// License.
//
// This product may include a number of subcomponents with separate copyright
// notices and license terms. Your use of these subcomponents is subject to the
// terms and conditions of the subcomponent's license, as noted in the LICENSE
// file.
//

#include "gtest/gtest.h"
#include "Logger.hpp"
#include "crypto/factory.hpp"
#include "crypto/openssl/EdDSA.hpp"
#include "crypto/openssl/EdDSASigner.hpp"
#include "crypto/openssl/EdDSAVerifier.hpp"
#include "crypto.hpp"

namespace {
using concord::crypto::KeyFormat;
using concord::crypto::generateEdDSAKeyPair;
using concord::crypto::EdDSAHexToPem;
using concord::util::crypto::openssl::EdDSAPrivateKey;
using concord::util::crypto::openssl::EdDSAPublicKey;
using concord::util::crypto::openssl::EdDSAPrivateKeyByteSize;
using concord::util::crypto::openssl::deserializeKey;

using TestTxnSigner = concord::crypto::openssl::EdDSASigner<EdDSAPrivateKey>;
using TestTxnVerifier = concord::crypto::openssl::EdDSAVerifier<EdDSAPublicKey>;

TEST(openssl_utils, check_eddsa_keys_hex_format_length) {
  const auto hexKeys = generateEdDSAKeyPair(KeyFormat::HexaDecimalStrippedFormat);
  ASSERT_EQ(hexKeys.first.size(), EdDSAPrivateKeyByteSize * 2);
  ASSERT_EQ(hexKeys.second.size(), EdDSAPrivateKeyByteSize * 2);
}

TEST(openssl_utils, generate_eddsa_keys_hex_format) {
  ASSERT_NO_THROW(generateEdDSAKeyPair());
  const auto hexKeys1 = generateEdDSAKeyPair();
  LOG_INFO(GL, hexKeys1.first << " | " << hexKeys1.second);

  ASSERT_NO_THROW(generateEdDSAKeyPair(KeyFormat::HexaDecimalStrippedFormat));
  const auto hexKeys2 = generateEdDSAKeyPair(KeyFormat::HexaDecimalStrippedFormat);
  LOG_INFO(GL, hexKeys2.first << " | " << hexKeys2.second);
}

TEST(openssl_utils, generate_eddsa_keys_pem_format) {
  ASSERT_NO_THROW(generateEdDSAKeyPair());
  ASSERT_NO_THROW(generateEdDSAKeyPair(KeyFormat::PemFormat));
  const auto pemKeys = generateEdDSAKeyPair(KeyFormat::PemFormat);
  LOG_INFO(GL, pemKeys.first << " | " << pemKeys.second);
}

TEST(openssl_utils, test_eddsa_keys_hex_ok) {
  auto hexKeys = generateEdDSAKeyPair();

  const auto signingKey = deserializeKey<EdDSAPrivateKey>(hexKeys.first);
  const auto verificationKey = deserializeKey<EdDSAPublicKey>(hexKeys.second);

  TestTxnSigner signer(signingKey.getBytes());
  TestTxnVerifier verifier(verificationKey.getBytes());

  const std::string data = "Hello VMworld";
  auto sig = signer.sign(data);
  ASSERT_TRUE(verifier.verify(data, sig));
}

TEST(openssl_utils, test_eddsa_keys_hex_nok) {
  const auto hexKeys = generateEdDSAKeyPair();

  const auto signingKey = deserializeKey<EdDSAPrivateKey>(hexKeys.first);
  const auto verificationKey = deserializeKey<EdDSAPublicKey>(hexKeys.second);

  TestTxnSigner signer(signingKey.getBytes());
  TestTxnVerifier verifier(verificationKey.getBytes());

  const std::string data = "Hello VMworld";
  auto sig = signer.sign(data);

  // Corrupt data.
  ++sig[0];

  ASSERT_FALSE(verifier.verify(data, sig));
}

TEST(openssl_utils, test_eddsa_keys_pem_ok) {
  const auto pemKeys = generateEdDSAKeyPair(KeyFormat::PemFormat);

  const auto signingKey = deserializeKey<EdDSAPrivateKey>(pemKeys.first, KeyFormat::PemFormat);
  const auto verificationKey = deserializeKey<EdDSAPublicKey>(pemKeys.second, KeyFormat::PemFormat);

  TestTxnSigner signer(signingKey.getBytes());
  TestTxnVerifier verifier(verificationKey.getBytes());

  const std::string data = "Hello VMworld";
  auto sig = signer.sign(data);
  ASSERT_TRUE(verifier.verify(data, sig));
}

TEST(openssl_utils, test_eddsa_keys_pem_nok) {
  const auto pemKeys = generateEdDSAKeyPair(KeyFormat::PemFormat);

  const auto signingKey = deserializeKey<EdDSAPrivateKey>(pemKeys.first, KeyFormat::PemFormat);
  const auto verificationKey = deserializeKey<EdDSAPublicKey>(pemKeys.second, KeyFormat::PemFormat);

  TestTxnSigner signer(signingKey.getBytes());
  TestTxnVerifier verifier(verificationKey.getBytes());

  const std::string data = "Hello VMworld";
  auto sig = signer.sign(data);

  // Corrupt data.
  ++sig[0];

  ASSERT_FALSE(verifier.verify(data, sig));
}

TEST(openssl_utils, test_eddsa_keys_combined_a_ok) {
  const auto hexKeys = generateEdDSAKeyPair();
  const auto pemKeys = EdDSAHexToPem(hexKeys);

  const auto signingKey = deserializeKey<EdDSAPrivateKey>(hexKeys.first);
  const auto verificationKey = deserializeKey<EdDSAPublicKey>(pemKeys.second, KeyFormat::PemFormat);

  TestTxnSigner signer(signingKey.getBytes());
  TestTxnVerifier verifier(verificationKey.getBytes());

  const std::string data = "Hello VMworld";
  auto sig = signer.sign(data);
  ASSERT_TRUE(verifier.verify(data, sig));
}

TEST(openssl_utils, test_eddsa_keys_combined_a_nok) {
  const auto hexKeys = generateEdDSAKeyPair();
  const auto pemKeys = EdDSAHexToPem(hexKeys);

  const auto signingKey = deserializeKey<EdDSAPrivateKey>(hexKeys.first);
  const auto verificationKey = deserializeKey<EdDSAPublicKey>(pemKeys.second, KeyFormat::PemFormat);

  TestTxnSigner signer(signingKey.getBytes());
  TestTxnVerifier verifier(verificationKey.getBytes());

  const std::string data = "Hello VMworld";
  auto sig = signer.sign(data);

  // Corrupt data.
  ++sig[0];

  ASSERT_FALSE(verifier.verify(data, sig));
}

TEST(openssl_utils, test_eddsa_keys_combined_b_ok) {
  const auto hexKeys = generateEdDSAKeyPair();
  const auto pemKeys = EdDSAHexToPem(hexKeys);

  const auto signingKey = deserializeKey<EdDSAPrivateKey>(pemKeys.first, KeyFormat::PemFormat);
  const auto verificationKey = deserializeKey<EdDSAPublicKey>(hexKeys.second);

  TestTxnSigner signer(signingKey.getBytes());
  TestTxnVerifier verifier(verificationKey.getBytes());

  const std::string data = "Hello VMworld";
  auto sig = signer.sign(data);
  ASSERT_TRUE(verifier.verify(data, sig));
}

TEST(openssl_utils, test_eddsa_keys_combined_b_nok) {
  const auto hexKeys = generateEdDSAKeyPair();
  const auto pemKeys = EdDSAHexToPem(hexKeys);

  const auto signingKey = deserializeKey<EdDSAPrivateKey>(pemKeys.first, KeyFormat::PemFormat);
  const auto verificationKey = deserializeKey<EdDSAPublicKey>(hexKeys.second);

  TestTxnSigner signer(signingKey.getBytes());
  TestTxnVerifier verifier(verificationKey.getBytes());

  std::string data = "Hello VMworld";
  auto sig = signer.sign(data);

  // Corrupt data.
  ++sig[0];

  ASSERT_FALSE(verifier.verify(data, sig));
}
}  // namespace

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}