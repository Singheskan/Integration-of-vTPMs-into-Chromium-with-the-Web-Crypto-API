// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef COMPONENTS_WEBCRYPTO_ALGORITHM_DISPATCH_H_
#define COMPONENTS_WEBCRYPTO_ALGORITHM_DISPATCH_H_

#include <stdint.h>

#include <memory>
#include <vector>

#include "third_party/blink/public/platform/web_crypto.h"

#include <dlfcn.h>  //dlopen
#include <iostream>
#include "third_party/tpm/tpm2-tss/include/tss2/tss2_common.h"
#include "third_party/tpm/tpm2-tss/include/tss2/tss2_esys.h"
#include "third_party/tpm/tpm2-tss/include/tss2/tss2_fapi.h"
#include "third_party/tpm/tpm2-tss/include/tss2/tss2_rc.h"
#include "third_party/boringssl/src/include/openssl/sha.h"

#define DUMMY_TPMT_TK_VERIFIED { .tag = TPM2_ST_VERIFIED , .hierarchy = TPM2_RH_OWNER, .digest = {0} }

#define ENGINE_HASH_ALG TPM2_ALG_SHA256

#define TPM2B_PUBLIC_ECC { \
    .size = 0, \
    .publicArea = { \
        .type = TPM2_ALG_ECC, \
        .nameAlg = TPM2_ALG_SHA256, \
        .objectAttributes = (TPMA_OBJECT_USERWITHAUTH | \
                                TPMA_OBJECT_SIGN_ENCRYPT | \
                                TPMA_OBJECT_NODA | \
                                TPMA_OBJECT_FIXEDTPM | \
                                TPMA_OBJECT_FIXEDPARENT | \
                                TPMA_OBJECT_SENSITIVEDATAORIGIN), \
        .authPolicy = { \
            .size = 0, \
        }, \
        .parameters{.eccDetail = {.symmetric = { \
                                        .algorithm = TPM2_ALG_NULL, \
                                        .keyBits{.aes = 256}, \
                                        .mode{.aes = TPM2_ALG_CFB}, \
                                    }, \
                                    .scheme = {.scheme = TPM2_ALG_ECDSA, .details = {.ecdsa = {.hashAlg = TPM2_ALG_SHA256}}}, \
                                    .curveID = TPM2_ECC_NIST_P256, \
                                    .kdf = {.scheme = TPM2_ALG_NULL, .details = {}}}}, \
        .unique{.ecc = {.x = {.size = 0, .buffer = {0x10, 0x20, 0x30, 0x40, 0x50, 0x60}}, .y = {.size = 0, .buffer = {}}}}, \
}};

#define TPM2B_PUBLIC_AES128GCM { \
    .size = 0, \
    .publicArea = { \
        .type = TPM2_ALG_SYMCIPHER, \
        .nameAlg = TPM2_ALG_SHA256, \
        .objectAttributes = (TPMA_OBJECT_USERWITHAUTH | \
                                 TPMA_OBJECT_SIGN_ENCRYPT | \
                                 TPMA_OBJECT_NODA | \
                                 TPMA_OBJECT_FIXEDTPM | \
                                 TPMA_OBJECT_FIXEDPARENT | \
                                 TPMA_OBJECT_SENSITIVEDATAORIGIN), \
        .authPolicy = { \
                .size = 0, \
            }, \
        .parameters{.symDetail = { \
                .sym = { \
                    .algorithm = TPM2_ALG_AES, \
                    .keyBits = {.aes = 128}, \
                    .mode = {.aes = TPM2_ALG_CFB}} \
            }}, \
        .unique{.sym = { \
                .size = 0, \
                .buffer = {0x10, 0x20, 0x30, 0x40, 0x50, 0x60} \
            }} \
}};

// for encryption
#define TPM2B_PUBLIC_PRIMARY_RSA_TEMPLATE { \
    .publicArea = { \
        .type = TPM2_ALG_RSA, \
        .nameAlg = ENGINE_HASH_ALG, \
        .objectAttributes = (TPMA_OBJECT_USERWITHAUTH | \
                             TPMA_OBJECT_DECRYPT | \
                             TPMA_OBJECT_NODA | \
                             TPMA_OBJECT_FIXEDTPM | \
                             TPMA_OBJECT_FIXEDPARENT | \
                             TPMA_OBJECT_SENSITIVEDATAORIGIN), \
        .authPolicy = { \
             .size = 0, \
         }, \
        .parameters{ \
          .rsaDetail = { \
             .symmetric = { \
                 .algorithm = TPM2_ALG_NULL, \
                 .keyBits{.aes = 128}, \
                 .mode{.aes = TPM2_ALG_CFB}, \
              }, \
             .scheme = { \
                .scheme = TPM2_ALG_NULL, \
                .details = {} \
             }, \
             .keyBits = 2048, \
             .exponent = 0,\
         }}, \
        .unique{.rsa{ \
             .size = 0, \
         }} \
     } \
}

// for signing
#define TPM2B_PUBLIC_PRIMARY_RSAPSS_TEMPLATE { \
        .size = 0, \
        .publicArea = { \
            .type = TPM2_ALG_RSA, \
            .nameAlg = TPM2_ALG_SHA256, \
            .objectAttributes = (TPMA_OBJECT_USERWITHAUTH | \
                                 TPMA_OBJECT_SIGN_ENCRYPT  | \
                                 TPMA_OBJECT_FIXEDTPM | \
                                 TPMA_OBJECT_FIXEDPARENT | \
                                 TPMA_OBJECT_NODA | \
                                 TPMA_OBJECT_SENSITIVEDATAORIGIN), \
            .authPolicy = { \
                 .size = 0, \
             }, \
            .parameters{ \
                .rsaDetail = { \
                 .symmetric = { \
                     .algorithm = TPM2_ALG_NULL, \
                     .keyBits{.aes = 128}, \
                     .mode{.aes = TPM2_ALG_CFB}, \
                 }, \
                 .scheme = { \
                      .scheme = TPM2_ALG_RSAPSS, \
                      .details = { \
                          .rsapss = { .hashAlg = TPM2_ALG_SHA256 } \
                      } \
                  }, \
                 .keyBits = 2048, \
                 .exponent = 0, \
             }}, \
            .unique{.rsa{ \
             .size = 0, \
             .buffer = {}, \
         }} \
        }, \
}


#define TPM2B_PUBLIC_KEY_TEMPLATE_HMAC { .size = 0, \
    .publicArea = { \
        .type = TPM2_ALG_KEYEDHASH, \
        .nameAlg = TPM2_ALG_SHA256, \
        .objectAttributes = (TPMA_OBJECT_USERWITHAUTH | \
                                 TPMA_OBJECT_SIGN_ENCRYPT  | \
                                 TPMA_OBJECT_FIXEDTPM | \
                                 TPMA_OBJECT_FIXEDPARENT | \
                                 TPMA_OBJECT_NODA | \
                                 TPMA_OBJECT_SENSITIVEDATAORIGIN), \
        .authPolicy = { .size = 0, .buffer = { 0 } }, \
        .parameters{.keyedHashDetail{.scheme = { .scheme = TPM2_ALG_HMAC, \
            .details = { .hmac = { .hashAlg = TPM2_ALG_SHA256 } } } } }, \
        .unique{.keyedHash = { .size = 0, .buffer = { 0x10, 0x20, 0x30, 0x40, 0x50, 0x60 }, } }, \
    }  \
}

#define DUMMY_RSA_DECRYPT { .scheme = TPM2_ALG_RSAPSS }

#define DUMMY_TPMT_SIGNATURE { \
        .sigAlg = TPM2_ALG_RSAPSS, \
        .signature = { \
            .rsapss = { \
                 .hash = TPM2_ALG_SHA1, .sig= {0} \
             } \
        } \
};

// for TPMImport
#define ESYS_TR_MIN_OBJECT (TPM2_RH_LAST + 1 + 0x1000)
#define DUMMY_TR_HANDLE_KEY ESYS_TR_MIN_OBJECT+1
#define DUMMY_2B_DATA  { \
        .size = 20, \
        .buffer = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, \
                   11, 12, 13, 14, 15, 16, 17, 18, 19, 20} \
}
#define DUMMY_2B_SECRET  { \
        .size = 20, \
        .secret = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, \
                   11, 12, 13, 14, 15, 16, 17, 18, 19, 20} \
}
#define DUMMY_SYMMETRIC {.algorithm = TPM2_ALG_AES, \
        .keyBits = {.aes = 128}, \
        .mode = {.aes = TPM2_ALG_CFB} \
}

#define DUMMY_IN_PUBLIC_DATA { \
    .size = 0, \
    .publicArea = { \
        .type = TPM2_ALG_ECC, \
        .nameAlg = TPM2_ALG_SHA256, \
        .objectAttributes = (TPMA_OBJECT_USERWITHAUTH | \
                                TPMA_OBJECT_RESTRICTED | \
                                TPMA_OBJECT_SIGN_ENCRYPT | \
                                TPMA_OBJECT_FIXEDTPM | \
                                TPMA_OBJECT_FIXEDPARENT | \
                                TPMA_OBJECT_SENSITIVEDATAORIGIN), \
        .authPolicy = { \
                .size = 0, \
            }, \
        .parameters{.eccDetail = { \
                .symmetric = { \
                    .algorithm = \
                    TPM2_ALG_AES, \
                    .keyBits{.aes = \
                    128}, \
                    .mode{.aes = \
                    TPM2_ALG_ECB}, \
                }, \
                .scheme = { \
                    .scheme = \
                    TPM2_ALG_ECDSA, \
                    .details = { \
                        .ecdsa = \
                        {. \
                        hashAlg \
                        = \
                        TPM2_ALG_SHA256}}, \
                }, \
                .curveID = TPM2_ECC_NIST_P256, \
                .kdf = { \
                    .scheme = TPM2_ALG_KDF1_SP800_56A, \
                    .details = {}} \
            }}, \
        .unique{.ecc = { \
                .x = {.size = 0,.buffer = {}}, \
                .y = {.size = 0,.buffer = {}}, \
            }}, \
    }, \
}

namespace webcrypto {

class CryptoData;
class GenerateKeyResult;
class Status;

// These functions provide an entry point for synchronous webcrypto operations.
//
// The inputs to these methods come from Blink, and hence the validations done
// by Blink can be assumed:
//
//   * The algorithm parameters are consistent with the algorithm
//   * The key contains the required usage for the operation

Status Encrypt(const blink::WebCryptoAlgorithm& algorithm,
               const blink::WebCryptoKey& key,
               const CryptoData& data,
               std::vector<uint8_t>* buffer);

Status Decrypt(const blink::WebCryptoAlgorithm& algorithm,
               const blink::WebCryptoKey& key,
               const CryptoData& data,
               std::vector<uint8_t>* buffer);

Status Digest(const blink::WebCryptoAlgorithm& algorithm,
              const CryptoData& data,
              std::vector<uint8_t>* buffer);

Status GenerateKey(const blink::WebCryptoAlgorithm& algorithm,
                   bool extractable,
                   blink::WebCryptoKeyUsageMask usages,
                   GenerateKeyResult* result);

Status ImportKey(blink::WebCryptoKeyFormat format,
                 const CryptoData& key_data,
                 const blink::WebCryptoAlgorithm& algorithm,
                 bool extractable,
                 blink::WebCryptoKeyUsageMask usages,
                 blink::WebCryptoKey* key);

Status ExportKey(blink::WebCryptoKeyFormat format,
                 const blink::WebCryptoKey& key,
                 std::vector<uint8_t>* buffer);

Status Sign(const blink::WebCryptoAlgorithm& algorithm,
            const blink::WebCryptoKey& key,
            const CryptoData& data,
            std::vector<uint8_t>* buffer);

Status Verify(const blink::WebCryptoAlgorithm& algorithm,
              const blink::WebCryptoKey& key,
              const CryptoData& signature,
              const CryptoData& data,
              bool* signature_match);

Status WrapKey(blink::WebCryptoKeyFormat format,
               const blink::WebCryptoKey& key_to_wrap,
               const blink::WebCryptoKey& wrapping_key,
               const blink::WebCryptoAlgorithm& wrapping_algorithm,
               std::vector<uint8_t>* buffer);

Status UnwrapKey(blink::WebCryptoKeyFormat format,
                 const CryptoData& wrapped_key_data,
                 const blink::WebCryptoKey& wrapping_key,
                 const blink::WebCryptoAlgorithm& wrapping_algorithm,
                 const blink::WebCryptoAlgorithm& algorithm,
                 bool extractable,
                 blink::WebCryptoKeyUsageMask usages,
                 blink::WebCryptoKey* key);

Status DeriveBits(const blink::WebCryptoAlgorithm& algorithm,
                  const blink::WebCryptoKey& base_key,
                  unsigned int length_bits,
                  std::vector<uint8_t>* derived_bytes);

// Derives a key by calling the underlying deriveBits/getKeyLength/importKey
// operations.
//
// Note that whereas the WebCrypto spec uses a single "derivedKeyType"
// AlgorithmIdentifier in its specification of deriveKey(), here two separate
// AlgorithmIdentifiers are used:
//
//   * |import_algorithm|  -- The parameters required by the derived key's
//                            "importKey" operation.
//
//   * |key_length_algorithm| -- The parameters required by the derived key's
//                               "get key length" operation.
//
// WebCryptoAlgorithm is not a flexible type like AlgorithmIdentifier (it cannot
// be easily re-interpreted as a different parameter type).
//
// Therefore being provided with separate parameter types for the import
// parameters and the key length parameters simplifies passing the right
// parameters onto ImportKey() and GetKeyLength() respectively.
Status DeriveKey(const blink::WebCryptoAlgorithm& algorithm,
                 const blink::WebCryptoKey& base_key,
                 const blink::WebCryptoAlgorithm& import_algorithm,
                 const blink::WebCryptoAlgorithm& key_length_algorithm,
                 bool extractable,
                 blink::WebCryptoKeyUsageMask usages,
                 blink::WebCryptoKey* derived_key);

bool SerializeKeyForClone(const blink::WebCryptoKey& key,
                          blink::WebVector<uint8_t>* key_data);

bool DeserializeKeyForClone(const blink::WebCryptoKeyAlgorithm& algorithm,
                            blink::WebCryptoKeyType type,
                            bool extractable,
                            blink::WebCryptoKeyUsageMask usages,
                            const CryptoData& key_data,
                            blink::WebCryptoKey* key);

// ---------------------------------------------------------------------------------------------------

Status DigestTest(const blink::WebCryptoAlgorithm& algorithm,
                const CryptoData& data,
                std::vector<uint8_t>* buffer);

Status TPMInit();

Status TPMGetRandom(std::vector<uint8_t>* buffer);

Status TPMCreatePrimary();

Status TPMCreatePrimarySignVerify();

Status TPMCreate();

Status TPMCreateSignVerify();

Status TPMEncrypt();

Status TPMDecrypt();

Status TPMRSAEncrypt(const blink::WebCryptoKey& key, const CryptoData& data, std::vector<uint8_t>* buffer);

Status TPMRSADecrypt(const blink::WebCryptoKey& key, const CryptoData& data, std::vector<uint8_t>* buffer);

Status TPMDoEncryptOrDecrypt(bool encrypt,
                          const std::vector<uint8_t>& raw_key,
                          const CryptoData& data,
                          unsigned int tag_length_bytes,
                          const CryptoData& iv,
                          const CryptoData& additional_data,
                          const EVP_AEAD* aead_alg,
                          std::vector<uint8_t>* buffer);

Status TPMSign();

Status TPMVerify();

Status TPMRSASign(const blink::WebCryptoKey& key, const CryptoData& data, std::vector<uint8_t>* buffer);

Status TPMRSAVerify(const blink::WebCryptoKey& key,
                    const CryptoData& signature,
                    const CryptoData& data,
                    bool* signature_match);

Status TPMFlushContext();

Status TPMImport(blink::WebCryptoKeyFormat format,
                    const CryptoData& key_data,
                    const blink::WebCryptoAlgorithm& algorithm,
                    bool extractable,
                    blink::WebCryptoKeyUsageMask usages,
                    blink::WebCryptoKey* key);

Status TPMExport(blink::WebCryptoKeyFormat format,
                    const blink::WebCryptoKey& key,
                    std::vector<uint8_t>* buffer);

Status TPMWritePublicKey(std::vector<uint8_t>* pk);

}  // namespace webcrypto

#endif  // COMPONENTS_WEBCRYPTO_ALGORITHM_DISPATCH_H_
