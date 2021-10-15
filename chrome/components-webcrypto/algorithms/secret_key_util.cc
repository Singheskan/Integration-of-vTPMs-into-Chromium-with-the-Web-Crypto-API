// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "components/webcrypto/algorithms/secret_key_util.h"
// #include "components/webcrypto/algorithm_dispatch.h"
#include "components/webcrypto/algorithms/util.h"
#include "components/webcrypto/blink_key_handle.h"
#include "components/webcrypto/crypto_data.h"
#include "components/webcrypto/generate_key_result.h"
#include "components/webcrypto/jwk.h"
#include "components/webcrypto/status.h"
#include "crypto/openssl_util.h"
#include "third_party/boringssl/src/include/openssl/rand.h"

namespace webcrypto {

Status GenerateWebCryptoSecretKey(const blink::WebCryptoKeyAlgorithm& algorithm,
                                  bool extractable,
                                  blink::WebCryptoKeyUsageMask usages,
                                  unsigned int keylen_bits,
                                  GenerateKeyResult* result) {
  // printf("Secret_key_util before:  \n");
  crypto::OpenSSLErrStackTracer err_tracer(FROM_HERE);
  unsigned int keylen_bytes = NumBitsToBytes(keylen_bits);
  std::vector<uint8_t> random_bytes(keylen_bytes, 0);
  // printf("%02x ", keylen_bytes);
  // printf("%0lx ", random_bytes.size());
  printf("\nSecret_key_util - GenerateWebCryptoSecretKey\n");
  
  // cb
  if (keylen_bytes > 0) {
    if (!RAND_bytes(random_bytes.data(), keylen_bytes))
      return Status::OperationError();
    TruncateToBitLength(keylen_bits, &random_bytes);
  }

  // TPMInit();
  // TPMCreatePrimary();
  // TPMCreate();
  // TPMSetRawKeyBytes(random_bytes.data());
  // printf("%02x ", random_bytes[0]);
  result->AssignSecretKey(blink::WebCryptoKey::Create(
      CreateSymmetricKeyHandle(CryptoData(random_bytes)),
      blink::kWebCryptoKeyTypeSecret, extractable, algorithm, usages));
  // printf("Secret_key_util after:  \n");
  // printf("%02x ", random_bytes[0]);
  return Status::Success();
}

Status CreateWebCryptoSecretKey(const CryptoData& key_data,
                                const blink::WebCryptoKeyAlgorithm& algorithm,
                                bool extractable,
                                blink::WebCryptoKeyUsageMask usages,
                                blink::WebCryptoKey* key) {
  printf("\nCreateWebCryptoSecretKey\n");
  
  *key = blink::WebCryptoKey::Create(CreateSymmetricKeyHandle(key_data),
                                     blink::kWebCryptoKeyTypeSecret,
                                     extractable, algorithm, usages);
  return Status::Success();
}

void WriteSecretKeyJwk(const CryptoData& raw_key_data,
                       const std::string& algorithm,
                       bool extractable,
                       blink::WebCryptoKeyUsageMask usages,
                       std::vector<uint8_t>* jwk_key_data) {
  JwkWriter writer(algorithm, extractable, usages, "oct");
  writer.SetBytes("k", raw_key_data);
  writer.ToJson(jwk_key_data);
}

Status ReadSecretKeyNoExpectedAlgJwk(
    const CryptoData& key_data,
    bool expected_extractable,
    blink::WebCryptoKeyUsageMask expected_usages,
    std::vector<uint8_t>* raw_key_data,
    JwkReader* jwk) {
  Status status = jwk->Init(key_data, expected_extractable, expected_usages,
                            "oct", std::string());
  if (status.IsError())
    return status;

  std::string jwk_k_value;
  status = jwk->GetBytes("k", &jwk_k_value);
  if (status.IsError())
    return status;
  raw_key_data->assign(jwk_k_value.begin(), jwk_k_value.end());

  return Status::Success();
}

}  // namespace webcrypto
