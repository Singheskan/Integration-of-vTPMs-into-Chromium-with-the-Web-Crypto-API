// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "components/webcrypto/algorithm_dispatch.h"
#include "components/webcrypto/blink_key_handle.h"
#include "components/webcrypto/algorithm_implementation.h"
#include "components/webcrypto/algorithm_implementations.h"
#include "components/webcrypto/algorithm_registry.h"
#include "components/webcrypto/crypto_data.h"
#include "components/webcrypto/generate_key_result.h"
#include "components/webcrypto/status.h"
#include "crypto/openssl_util.h"
#include "third_party/blink/public/platform/web_crypto_key_algorithm.h"

#include <stdio.h> // cb
#include <array>

namespace webcrypto {

namespace {

Status DecryptDontCheckKeyUsage(const blink::WebCryptoAlgorithm& algorithm,
                                const blink::WebCryptoKey& key,
                                const CryptoData& data,
                                std::vector<uint8_t>* buffer) {
  if (algorithm.Id() != key.Algorithm().Id())
    return Status::ErrorUnexpected();

  const AlgorithmImplementation* impl = nullptr;
  Status status = GetAlgorithmImplementation(algorithm.Id(), &impl);
  if (status.IsError())
    return status;

  return impl->Decrypt(algorithm, key, data, buffer);
}

Status EncryptDontCheckUsage(const blink::WebCryptoAlgorithm& algorithm,
                             const blink::WebCryptoKey& key,
                             const CryptoData& data,
                             std::vector<uint8_t>* buffer) {
  if (algorithm.Id() != key.Algorithm().Id())
    return Status::ErrorUnexpected();

  const AlgorithmImplementation* impl = nullptr;
  Status status = GetAlgorithmImplementation(algorithm.Id(), &impl);
  if (status.IsError())
    return status;

  return impl->Encrypt(algorithm, key, data, buffer);
}

Status ExportKeyDontCheckExtractability(blink::WebCryptoKeyFormat format,
                                        const blink::WebCryptoKey& key,
                                        std::vector<uint8_t>* buffer) {
  const AlgorithmImplementation* impl = nullptr;
  Status status = GetAlgorithmImplementation(key.Algorithm().Id(), &impl);
  if (status.IsError())
    return status;

  return impl->ExportKey(format, key, buffer);
}

}  // namespace

Status Encrypt(const blink::WebCryptoAlgorithm& algorithm,
               const blink::WebCryptoKey& key,
               const CryptoData& data,
               std::vector<uint8_t>* buffer) {
  if (!key.KeyUsageAllows(blink::kWebCryptoKeyUsageEncrypt))
    return Status::ErrorUnexpected();
  printf("WCA - Encrypt \n");
  return EncryptDontCheckUsage(algorithm, key, data, buffer);
}

Status Decrypt(const blink::WebCryptoAlgorithm& algorithm,
               const blink::WebCryptoKey& key,
               const CryptoData& data,
               std::vector<uint8_t>* buffer) {
  if (!key.KeyUsageAllows(blink::kWebCryptoKeyUsageDecrypt))
    return Status::ErrorUnexpected();
  printf("WCA - Decrypt \n");
  return DecryptDontCheckKeyUsage(algorithm, key, data, buffer);
}

Status Digest(const blink::WebCryptoAlgorithm& algorithm,
              const CryptoData& data,
              std::vector<uint8_t>* buffer) {
  const AlgorithmImplementation* impl = nullptr;
  Status status = GetAlgorithmImplementation(algorithm.Id(), &impl);
  if (status.IsError())
    return status;

  return impl->Digest(algorithm, data, buffer);
}

Status DigestTest(const blink::WebCryptoAlgorithm& algorithm,
              const CryptoData& data,
              std::vector<uint8_t>* buffer) {
  const AlgorithmImplementation* impl = nullptr;
  Status status = GetAlgorithmImplementation(algorithm.Id(), &impl);
  if (status.IsError())
    return status;

  return impl->DigestTest(algorithm, data, buffer);
}

// ---------------------------------------------------------------------------------

// TSS2_RC r;
// ESYS_CONTEXT* ctx;
// ESYS_TR parent_handle = ESYS_TR_RH_OWNER;
// ESYS_TR loadedKeyHandle = ESYS_TR_NONE;
// // Status createPrimary pass to Sign and FlushContext
// ESYS_TR parent = ESYS_TR_NONE;
// // Status sign pass to Verify

void* handle;
ESYS_CONTEXT* esys_context;
TSS2_RC r;
ESYS_TR primaryHandle = ESYS_TR_NONE;
ESYS_TR loadedKeyHandle = ESYS_TR_NONE;

Status TPMInit() {
  // TSS2_RC r;
  // ESYS_CONTEXT* ctx;
  // void* handle;
  // chromium is sandboxed - it is not allowed to perform arbitrary system calls
  // or open arbitrary files. exec chromium with --no-sandbox
  if ((esys_context != NULL) || !(handle = dlopen("libtss2-esys.so", RTLD_LAZY))) { // TODO: Reset TPM and create new primary without crashing browser
    puts("here dlopen");
    fprintf(stderr, "%s\n", dlerror());
    abort();
  }
  printf("------------- handle not null \n");

  /*TSS2_RC Esys_Initialize 	( 	ESYS_CONTEXT **  	esys_context,
		TSS2_TCTI_CONTEXT *  	tcti,
		TSS2_ABI_VERSION *  	abiVersion 
	) 	*/
  TSS2_RC(*Esys_Initialize)(ESYS_CONTEXT**, TSS2_TCTI_CONTEXT*, TSS2_ABI_VERSION*) =
  (TSS2_RC(*)(ESYS_CONTEXT**, TSS2_TCTI_CONTEXT*, TSS2_ABI_VERSION*))dlsym(handle, "Esys_Initialize");
  r = (*Esys_Initialize)(&esys_context, NULL, NULL);
  if (r != TSS2_RC_SUCCESS) {
    printf("\nError: Esys_Initialize\n");
    abort();
  }
  printf("------------- init done \n");

  /*TSS2_RC Esys_SelfTest 	( 	ESYS_CONTEXT *  	esysContext,
		ESYS_TR  	shandle1,
		ESYS_TR  	shandle2,
		ESYS_TR  	shandle3,
		TPMI_YES_NO  	fullTest 
	) 	*/
  TSS2_RC(*Esys_SelfTest) (ESYS_CONTEXT*, ESYS_TR, ESYS_TR, ESYS_TR, TPMI_YES_NO) = 
  (TSS2_RC(*)(ESYS_CONTEXT*, ESYS_TR, ESYS_TR, ESYS_TR, TPMI_YES_NO))dlsym(handle, "Esys_SelfTest");
  r = (*Esys_SelfTest)(esys_context, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, true);
  if (r != TSS2_RC_SUCCESS) {
    printf("\nError: Esys_SelfTest\n");
    abort();
  }
  printf("------------- TPM Full SelfTest done \n");
  return Status::Success();
}

Status TPMGetRandom(std::vector<uint8_t>* buffer) {
  // Erstelle function pointer "Esys_GetRandom" der ein TSS2_RC zurückliefert
  // und als Paramter ein ESYS_CONTEXT Pointer nimmt.
  // Zuweisung zu einem dlsym void pointer, der zum gleichen Rückgabewert und
  // Typ gecastet wird.
  if (esys_context == NULL) {
    TPMInit();
  }
  printf("------------- start getrandom \n");
  TPM2B_DIGEST* random_bytes;                        

  /*TSS2_RC Esys_GetRandom 	( 	ESYS_CONTEXT *  	esysContext,
  ESYS_TR  	shandle1,
  ESYS_TR  	shandle2,
  ESYS_TR  	shandle3,
  UINT16  	bytesRequested,
  TPM2B_DIGEST **  	randomBytes 
  ) 	*/
  TSS2_RC(*Esys_GetRandom)(ESYS_CONTEXT*, ESYS_TR, ESYS_TR, ESYS_TR, UINT16, TPM2B_DIGEST**) =
  (TSS2_RC(*)(ESYS_CONTEXT*, ESYS_TR, ESYS_TR, ESYS_TR, UINT16,TPM2B_DIGEST**))dlsym(handle, "Esys_GetRandom");
  r = (*Esys_GetRandom)(esys_context, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, 16, &random_bytes); // fixed on 16 bytes
  if (r != TSS2_RC_SUCCESS) {
    printf("\nError: Esys_GetRandom\nError:%s\n", strerror(errno));
    abort();
  }

  // Write TPM2B_Digest random_buffer into webarray buffer and display in console
  buffer->resize(random_bytes->size);
  uint8_t* p = buffer->data();
  printf("------------- GetRandom:");
  //printf(random_bytes);
  for (int i = 0; i < random_bytes->size; i++) {
    *p = random_bytes->buffer[i];
    ++p;
    printf("0x%x ", random_bytes->buffer[i]);
  }
  printf("\n");

  // dlclose(handle);
  if (dlerror()) {
    puts("here dlsym");
    fprintf(stderr, "%s\n", dlerror());
    abort();
  }

  return Status::Success();
}

  TPM2B_PUBLIC inPublic = {
      .size = 0,
      .publicArea = {
          .type = TPM2_ALG_RSA,
          .nameAlg = TPM2_ALG_SHA256,
          .objectAttributes = (TPMA_OBJECT_USERWITHAUTH |
                                TPMA_OBJECT_NODA |
                                TPMA_OBJECT_DECRYPT |
                                TPMA_OBJECT_FIXEDTPM |
                                TPMA_OBJECT_FIXEDPARENT |
                                TPMA_OBJECT_SENSITIVEDATAORIGIN),
          .authPolicy = {
                .size = 0,
            },
          .parameters{.rsaDetail = {
                .symmetric = {
                    .algorithm = TPM2_ALG_NULL},
                .scheme = { .scheme = TPM2_ALG_OAEP, .details = {.oaep = {.hashAlg = TPM2_ALG_SHA256}}},
                .keyBits = 2048,
                .exponent = 0,
            }},
          .unique{.rsa = {
                .size = 0,
                .buffer = {},
            }},
      },
  };

Status TPMCreatePrimarySignVerify() {
  printf("\n------------- TPMCreatePrimarySignVerify\n");
  inPublic = { 
        .size = 0, 
        .publicArea = { 
            .type = TPM2_ALG_RSA, 
            .nameAlg = TPM2_ALG_SHA256, 
            .objectAttributes = (TPMA_OBJECT_USERWITHAUTH | 
                                 TPMA_OBJECT_SIGN_ENCRYPT  | 
                                 TPMA_OBJECT_FIXEDTPM | 
                                 TPMA_OBJECT_FIXEDPARENT | 
                                 TPMA_OBJECT_NODA | 
                                 TPMA_OBJECT_SENSITIVEDATAORIGIN), 
            .authPolicy = { 
                 .size = 0, 
             }, 
            .parameters{ 
                .rsaDetail = { 
                 .symmetric = { 
                     .algorithm = TPM2_ALG_NULL, 
                     .keyBits{.aes = 128}, 
                     .mode{.aes = TPM2_ALG_CFB}, 
                 }, 
                 .scheme = { 
                      .scheme = TPM2_ALG_RSAPSS, 
                      .details = { 
                          .rsapss = { .hashAlg = TPM2_ALG_SHA256 } 
                      } 
                  }, 
                 .keyBits = 2048, 
                 .exponent = 0, 
             }}, 
            .unique{.rsa{ 
             .size = 0, 
             .buffer = {}, 
         }} 
        }, 
    };

  return TPMCreatePrimary();
}

TPM2B_PUBLIC *outPublic = NULL;
Status TPMCreatePrimary() {
  /* What I want to do (using tpm2-tools instructions):
    1. tpm2_createprimary --hierarchy o --out-context pri.ctx
    2. tpm2_create --context-parent pri.ctx --pubfile sub.pub --privfile sub.priv
        --out-context sub.ctx
    3. openssl dgst -sha1 -binary -out hash.bin msg.txt
    4. tpm2_sign --key-context file:subctx --format plain --digest hash.bin --sig
    hash.plain
    5. tpm2_readpublic -c "file:sub.ctx" --format der --out-file sub-pub.der
    6. openssl dgst -verify sub-pub.der -keyform der sha1 -signature
    hash.plain msg.txt
  */
  if (esys_context == NULL) {
    TPMInit();
  }
  if (primaryHandle != ESYS_TR_NONE) {  // TODO: Reset TPM and create new primary without crashing browser
    printf("\nPrimaryKey was already created.");
    return Status::Success();
  }
  TPM2B_CREATION_DATA *creationData = NULL;
  TPM2B_DIGEST *creationHash = NULL;
  TPMT_TK_CREATION *creationTicket = NULL;


  TPM2B_SENSITIVE_CREATE inSensitivePrimary = {
    .size = 0,
    .sensitive = {
        .userAuth = {
              .size = 5, 
              .buffer = {1, 2, 3, 4, 5} 
          },
        .data = {
              .size = 0,
              .buffer = {0},
          },
    },
  };

  // TPM2B_PUBLIC inPublic = {
  //       .size = 0,
  //       .publicArea = {
  //           .type = TPM2_ALG_RSA,
  //           .nameAlg = TPM2_ALG_SHA256,
  //           .objectAttributes = (TPMA_OBJECT_USERWITHAUTH |
  //                                TPMA_OBJECT_RESTRICTED |
  //                                TPMA_OBJECT_NODA |
  //                                TPMA_OBJECT_DECRYPT |
  //                                TPMA_OBJECT_FIXEDTPM |
  //                                TPMA_OBJECT_FIXEDPARENT |
  //                                TPMA_OBJECT_SENSITIVEDATAORIGIN),
  //           .authPolicy = {
  //                .size = 0,
  //            },
  //           .parameters{.rsaDetail = {
  //                .symmetric = {
  //                    .algorithm = TPM2_ALG_AES,
  //                    .keyBits{.aes = 128},
  //                    .mode{.aes = TPM2_ALG_CFB}},
  //                .scheme = {
  //                     .scheme = TPM2_ALG_NULL
  //                 },
  //                .keyBits = 2048,
  //                .exponent = 0,
  //            }},
  //           .unique{.rsa = {
  //                .size = 0,
  //                .buffer = {},
  //            }},
  //       },
  //   };

  /*
    data that will be included in the creation data for this 
    object to provide permanent, verifiable linkage between 
    this object and some object owner data
  */
  TPM2B_DATA outsideInfo = {
      .size = 0,
      .buffer = {},
  };

  TPML_PCR_SELECTION creationPCR = {
      .count = 0,
  };

  TPM2B_AUTH authValuePrimary = {
      .size = 5,
      .buffer = {1, 2, 3, 4, 5}
  };

  TPM2B_AUTH authValue = {
      .size = 0,
      .buffer = {}
  };


  TSS2_RC(*Esys_TR_SetAuth)(ESYS_CONTEXT*, ESYS_TR, TPM2B_AUTH const *) =
  (TSS2_RC(*)(ESYS_CONTEXT*, ESYS_TR, TPM2B_AUTH const *))dlsym(handle, "Esys_TR_SetAuth");
  r = Esys_TR_SetAuth(esys_context, ESYS_TR_RH_OWNER, &authValue);

  /*TSS2_RC Esys_CreatePrimary 	( 	ESYS_CONTEXT *  	esysContext,
    ESYS_TR  	primaryHandle,
    ESYS_TR  	shandle1,
    ESYS_TR  	shandle2,
    ESYS_TR  	shandle3,
    const TPM2B_SENSITIVE_CREATE *  	inSensitive,
    const TPM2B_PUBLIC *  	inPublic,
    const TPM2B_DATA *  	outsideInfo,
    const TPML_PCR_SELECTION *  	creationPCR,
    ESYS_TR *  	objectHandle,
    TPM2B_PUBLIC **  	outPublic,
    TPM2B_CREATION_DATA **  	creationData,
    TPM2B_DIGEST **  	creationHash,
    TPMT_TK_CREATION **  	creationTicket 
    ) 	
  */

  printf("------------- CreatePrimary\n");
  TSS2_RC(*Esys_CreatePrimary)(ESYS_CONTEXT*, ESYS_TR, ESYS_TR, ESYS_TR, ESYS_TR,
    const TPM2B_SENSITIVE_CREATE*, const TPM2B_PUBLIC*, const TPM2B_DATA*,
    const TPML_PCR_SELECTION*, ESYS_TR*, TPM2B_PUBLIC**,
    TPM2B_CREATION_DATA**, TPM2B_DIGEST**, TPMT_TK_CREATION**) =
      (TSS2_RC(*)(ESYS_CONTEXT*, ESYS_TR, ESYS_TR, ESYS_TR, ESYS_TR,
    const TPM2B_SENSITIVE_CREATE*, const TPM2B_PUBLIC*, const TPM2B_DATA*,
    const TPML_PCR_SELECTION*, ESYS_TR*, TPM2B_PUBLIC**,
    TPM2B_CREATION_DATA**, TPM2B_DIGEST**, TPMT_TK_CREATION**))dlsym(handle, "Esys_CreatePrimary");

    r = Esys_CreatePrimary(esys_context, ESYS_TR_RH_OWNER, ESYS_TR_PASSWORD,
                        ESYS_TR_NONE, ESYS_TR_NONE,
                        &inSensitivePrimary, &inPublic,
                        &outsideInfo, &creationPCR, &primaryHandle,
                        &outPublic, &creationData, &creationHash,
                        &creationTicket);

  if (r != TSS2_RC_SUCCESS) {
    printf("\nError in Esys_CreatePrimary\nError:%s\n",
            strerror(errno));
    abort();
  }

  // TSS2_RC(*Esys_Free)(void *) = (TSS2_RC(*)(void *))dlsym(handle, "Esys_Free");
  // r = Esys_Free(outPublic);

  printf("\nPublic Key:\n");
  for (int v = 0; v < outPublic->publicArea.unique.keyedHash.size; v++)
  {
      printf("%02x ", outPublic->publicArea.unique.keyedHash.buffer[v]);
  }
  // printf("\nPrivate Key:\n");
  // printf("size: %02x ", inSensitivePrimary.sensitive.data.size);
  // for(int v = 0; v < inSensitivePrimary.sensitive.data.size; v++) {
  //   printf("%02x ", inSensitivePrimary.sensitive.data.buffer[v]);
  // }
  printf("\n------------- CreatePrimary done\n");

  /*
    TSS2_RC Esys_TR_SetAuth 	( 	ESYS_CONTEXT *  	esys_context,
                                  ESYS_TR  	esys_handle,
                                  TPM2B_AUTH const *  	authValue 
    ) 	
  */

  r = Esys_TR_SetAuth(esys_context, primaryHandle, &authValuePrimary);

  if (r != TSS2_RC_SUCCESS) {
    printf("\nError in Esys_TR_SetAuth\nError:%s\n",
            strerror(errno));
    abort();
  }

  // TPMCreate();

  return Status::Success();
}



TPM2B_PRIVATE *outPrivate2 = NULL;  
TPM2B_PUBLIC *outPublic2 = NULL;

Status TPMCreateSignVerify() {
  printf("\n------------- TPMCreateSignVerify\n");
  return Status::Success();
}

Status TPMCreate() {
  printf("------------- Create\n");
  TPM2B_AUTH authKey2 = {
      .size = 6,
      .buffer = {6, 7, 8, 9, 10, 11}
  };

  TPM2B_SENSITIVE_CREATE inSensitive2 = {
      .size = 0,
      .sensitive = {
          .userAuth = {
                .size = 6,
                .buffer = {6, 7, 8, 9, 10, 11}
            },
          .data = {
                .size = 16,
                .buffer = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 16}
            }
      }
  };

  //inSensitive2.sensitive.userAuth = authKey2;

  // TPM2B_PUBLIC inPublic2 = {
  //     .size = 0,
  //     .publicArea = {
  //         .type = TPM2_ALG_RSA,
  //         .nameAlg = TPM2_ALG_SHA256,
  //         .objectAttributes = (TPMA_OBJECT_USERWITHAUTH |
  //                               TPMA_OBJECT_SIGN_ENCRYPT |
  //                               TPMA_OBJECT_NODA |
  //                               TPMA_OBJECT_DECRYPT),
  //         .authPolicy = {
  //               .size = 0,
  //           },
  //         .parameters{.rsaDetail = {
  //               .symmetric = {
  //                   .algorithm = TPM2_ALG_NULL,
  //                   .keyBits = {.aes = 128},
  //                   .mode = {.aes = TPM2_ALG_CFB}}
  //           }},
  //         .unique{.rsa = {
  //               .size = 0,
  //               .buffer = {}
  //           }}
  //     }
  // };

  // TPM2B_PUBLIC inPublic2 = {
  //   .size = 0,
  //   .publicArea = {
  //       .type = TPM2_ALG_RSA,
  //       .nameAlg = TPM2_ALG_SHA256,
  //       .objectAttributes = (TPMA_OBJECT_USERWITHAUTH |
  //                                TPMA_OBJECT_SIGN_ENCRYPT |
  //                                TPMA_OBJECT_DECRYPT),
  //       .authPolicy = {
  //             .size = 0,
  //         },
  //       .parameters{.rsaDetail = {
  //             .symmetric = {
  //                 .algorithm = TPM2_ALG_NULL},
  //             .scheme = { .scheme = TPM2_ALG_OAEP, .details = {.oaep = {.hashAlg = TPM2_ALG_SHA256}}},
  //             .keyBits = 2048,
  //             .exponent = 0,
  //         }},
  //       .unique{.rsa = {
  //             .size = 0,
  //             .buffer = {},
  //         }},
  //   },
  // };

   TPM2B_PUBLIC inPublic2 = {
        .size = 0,
        .publicArea = {
            .type = TPM2_ALG_SYMCIPHER,
            .nameAlg = TPM2_ALG_SHA256,
            .objectAttributes = (TPMA_OBJECT_USERWITHAUTH |
                                 TPMA_OBJECT_SIGN_ENCRYPT |
                                 TPMA_OBJECT_DECRYPT),

            .authPolicy = {
                 .size = 0,
             },
            .parameters{.symDetail = {
                 .sym = {
                     .algorithm = TPM2_ALG_AES,
                     .keyBits = {.aes = 128},
                     .mode = {.aes = TPM2_ALG_CFB}}
             }},
            .unique{.sym = {
                 .size = 0,
                 .buffer = {}
             }}
        }
    };

  TPM2B_DATA outsideInfo2 = {
      .size = 0,
      .buffer = {}
      ,
  };

  TPML_PCR_SELECTION creationPCR2 = {
      .count = 0,
  };

  TPM2B_CREATION_DATA *creationData2 = NULL;
  TPM2B_DIGEST *creationHash2 = NULL;
  TPMT_TK_CREATION *creationTicket2 = NULL;
  // TPM2B_PUBLIC *outPublic2 = NULL;
  // TPM2B_PRIVATE *outPrivate2 = NULL;

  /*
    Esys_Create (ESYS_CONTEXT *esysContext, 
              ESYS_TR parentHandle, 
              ESYS_TR shandle1, 
              ESYS_TR shandle2, 
              ESYS_TR shandle3, 
              const TPM2B_SENSITIVE_CREATE *inSensitive, 
              const TPM2B_PUBLIC *inPublic, 
              const TPM2B_DATA *outsideInfo, 
              const TPML_PCR_SELECTION *creationPCR, 
              TPM2B_PRIVATE **outPrivate, 
              TPM2B_PUBLIC **outPublic, 
              TPM2B_CREATION_DATA **creationData, 
              TPM2B_DIGEST **creationHash, 
              TPMT_TK_CREATION **creationTicket)
  */
  TSS2_RC(*Esys_Create)(ESYS_CONTEXT*, ESYS_TR, ESYS_TR, ESYS_TR, ESYS_TR,
  const TPM2B_SENSITIVE_CREATE*, const TPM2B_PUBLIC*, const TPM2B_DATA*,
  const TPML_PCR_SELECTION*, TPM2B_PRIVATE **, TPM2B_PUBLIC **, TPM2B_CREATION_DATA **, 
  TPM2B_DIGEST **, TPMT_TK_CREATION **) =
    (TSS2_RC(*)(ESYS_CONTEXT*, ESYS_TR, ESYS_TR, ESYS_TR, ESYS_TR,
  const TPM2B_SENSITIVE_CREATE*, const TPM2B_PUBLIC*, const TPM2B_DATA*,
  const TPML_PCR_SELECTION*, TPM2B_PRIVATE **, TPM2B_PUBLIC **, TPM2B_CREATION_DATA **, 
  TPM2B_DIGEST **, TPMT_TK_CREATION **))dlsym(handle, "Esys_Create");

  r = Esys_Create(esys_context,
                  primaryHandle,
                  ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                  &inSensitive2,
                  &inPublic2,
                  &outsideInfo2,
                  &creationPCR2,
                  &outPrivate2,
                  &outPublic2,
                  &creationData2, &creationHash2, &creationTicket2);

    if (r != TSS2_RC_SUCCESS) {
    printf("\nError in Esys_Create\nError:%s\n",
            strerror(errno));
    abort();
  }

  printf("------------- Create done\n");

  /*
  Esys_Load (ESYS_CONTEXT *esysContext, 
            ESYS_TR parentHandle, 
            ESYS_TR shandle1, 
            ESYS_TR shandle2, 
            ESYS_TR shandle3, 
            const TPM2B_PRIVATE *inPrivate, 
            const TPM2B_PUBLIC *inPublic, 
            ESYS_TR *objectHandle)
  */
  TSS2_RC(*Esys_Load)(ESYS_CONTEXT*, ESYS_TR, ESYS_TR, ESYS_TR, ESYS_TR, 
  const TPM2B_PRIVATE *, const TPM2B_PUBLIC *, ESYS_TR *) =
    (TSS2_RC(*)(ESYS_CONTEXT*, ESYS_TR, ESYS_TR, ESYS_TR, ESYS_TR, 
  const TPM2B_PRIVATE *, const TPM2B_PUBLIC *, ESYS_TR *))dlsym(handle, "Esys_Load");

  r = Esys_Load(esys_context,
                primaryHandle,
                ESYS_TR_PASSWORD,
                ESYS_TR_NONE,
                ESYS_TR_NONE, outPrivate2, outPublic2, &loadedKeyHandle);

  if (r != TSS2_RC_SUCCESS) {
    printf("\nError in Esys_Load\nError:%s\n",
            strerror(errno));
    abort();
  }

  printf("------------- Load RSA Key done\n");
  // printf("\nAES Public Key:\n");
  // for (int v = 0; v < (*outPublic2).publicArea.unique.keyedHash.size; v++)
  // {
  //     printf("%02x ", (*outPublic2).publicArea.unique.keyedHash.buffer[v]);
  // }
  TSS2_RC(*Esys_TR_SetAuth)(ESYS_CONTEXT*, ESYS_TR, TPM2B_AUTH const *) =
  (TSS2_RC(*)(ESYS_CONTEXT*, ESYS_TR, TPM2B_AUTH const *))dlsym(handle, "Esys_TR_SetAuth");
  r = Esys_TR_SetAuth(esys_context, loadedKeyHandle, &authKey2);

  if (r != TSS2_RC_SUCCESS) {
    printf("\nError in Esys_TR_SetAuth\nError:%s\n",
            strerror(errno));
    abort();
  }
  return Status::Success();
}



TPM2B_PUBLIC_KEY_RSA *cipher = NULL;

Status TPMRSAEncrypt(const blink::WebCryptoKey& key, const CryptoData& data, std::vector<uint8_t>* buffer) {
  TPM2B_DATA * null_data = NULL;
  printf("\n------------- TPM_RSA_Encrypt\n");
  if (esys_context == NULL) {
    printf("\n------------- TPM_RSA_Encrypt ctx was null\n");
    TPMInit();
    // TPMCreatePrimary();
    // TPMCreate();
  }
  if (primaryHandle == ESYS_TR_NONE) {
    printf("\n------------- TPM_RSA_Encrypt primary was null\n");
    TPMCreatePrimary();
  }
  // TPMCreate();
  //TPMI_YES_NO decrypt = TPM2_YES;
  // TPMI_YES_NO encrypt = TPM2_NO;
  // ESYS_TR keyHandle_handle = loadedKeyHandle;

  size_t plain_size = data.byte_length();
  TPM2B_PUBLIC_KEY_RSA plain = {.size = plain_size, .buffer = {}};
  printf("\nTPMRSAEncrypt Input: ");
  for (int v = 0; v < (int) plain.size; v++) {
    plain.buffer[v] = data.bytes()[v];
    printf("%02x ", plain.buffer[v]);
  }
  printf("\n");

  TPMT_RSA_DECRYPT scheme;
  scheme.scheme = TPM2_ALG_OAEP;
  scheme.details.oaep.hashAlg = TPM2_ALG_SHA256;

  /*
    Esys_RSA_Encrypt (
      ESYS_CONTEXT *esysContext, 
      ESYS_TR keyHandle, 
      ESYS_TR shandle1, 
      ESYS_TR shandle2, 
      ESYS_TR shandle3, 
      const TPM2B_PUBLIC_KEY_RSA *message, 
      const TPMT_RSA_DECRYPT *inScheme, 
      const TPM2B_DATA *label, 
      TPM2B_PUBLIC_KEY_RSA **outData
      )
  */
  TSS2_RC(*Esys_RSA_Encrypt)(ESYS_CONTEXT*, ESYS_TR, ESYS_TR, ESYS_TR, ESYS_TR, const TPM2B_PUBLIC_KEY_RSA*, 
      const TPMT_RSA_DECRYPT*, const TPM2B_DATA*, TPM2B_PUBLIC_KEY_RSA**) =
    (TSS2_RC(*)(ESYS_CONTEXT*, ESYS_TR, ESYS_TR, ESYS_TR, ESYS_TR, const TPM2B_PUBLIC_KEY_RSA*, 
      const TPMT_RSA_DECRYPT*, const TPM2B_DATA*, TPM2B_PUBLIC_KEY_RSA**))dlsym(handle, "Esys_RSA_Encrypt");
  r = Esys_RSA_Encrypt(
      esys_context,
      primaryHandle,
      ESYS_TR_NONE,
      ESYS_TR_NONE,
      ESYS_TR_NONE,
      &plain, 
      &scheme,
      null_data, 
      &cipher);

  if (r != TSS2_RC_SUCCESS) {
    printf("\nError in Esys_RSA_Encrypt\nError:%s\n",
            strerror(errno));
    abort();
  }

  buffer->resize(cipher->size);
  uint8_t* p = buffer->data();
  for (int i = 0; i < cipher->size; i++) {
    *p = cipher->buffer[i];
    ++p;
    // printf("0x%x ", outData2->buffer[i]);
  }

  printf("\nTPMRSAEncrypt - Encrypted Output: ");
  for (int v = 0; v < (int) cipher->size; v++)
  {
    printf("%02x ", cipher->buffer[v]);
  }
  printf("\n------------- TPM_RSA_Encrypt done\n");
  return Status::Success();
}

Status TPMRSADecrypt(const blink::WebCryptoKey& key, const CryptoData& data, std::vector<uint8_t>* buffer) {
  printf("------------- TPM_RSA_Decrypt\n");
  // TPMI_YES_NO decrypt = TPM2_YES;
  //TPMI_YES_NO encrypt = TPM2_NO;
  // ESYS_TR keyHandle_handle = loadedKeyHandle;

  TPMT_RSA_DECRYPT scheme;
  scheme.scheme = TPM2_ALG_OAEP;
  scheme.details.oaep.hashAlg = TPM2_ALG_SHA256;
  TPM2B_PUBLIC_KEY_RSA *plain2 = NULL;
  TPM2B_DATA * null_data = NULL;
  
  /*
  Esys_RSA_Decrypt (
    ESYS_CONTEXT *esysContext, 
    ESYS_TR keyHandle, 
    ESYS_TR shandle1, 
    ESYS_TR shandle2, 
    ESYS_TR shandle3, 
    const TPM2B_PUBLIC_KEY_RSA *cipherText, 
    const TPMT_RSA_DECRYPT *inScheme, 
    const TPM2B_DATA *label, 
    TPM2B_PUBLIC_KEY_RSA **message
    )
  */
  TSS2_RC(*Esys_RSA_Decrypt)(ESYS_CONTEXT*, ESYS_TR, ESYS_TR, ESYS_TR, ESYS_TR, const TPM2B_PUBLIC_KEY_RSA*, 
  const TPMT_RSA_DECRYPT*, const TPM2B_DATA* , TPM2B_PUBLIC_KEY_RSA**) =
    (TSS2_RC(*)(ESYS_CONTEXT*, ESYS_TR, ESYS_TR, ESYS_TR, ESYS_TR, const TPM2B_PUBLIC_KEY_RSA*, 
  const TPMT_RSA_DECRYPT*, const TPM2B_DATA* , TPM2B_PUBLIC_KEY_RSA**))dlsym(handle, "Esys_RSA_Decrypt");
  r = Esys_RSA_Decrypt(esys_context, primaryHandle, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE, 
                        cipher, &scheme, null_data, &plain2);

  if (r != TSS2_RC_SUCCESS) {
    printf("\nError in Esys_RSA_Decrypt - Decrypt\nError:%s\n",
            strerror(errno));
    abort();
  }
  buffer->resize(plain2->size);
  uint8_t* p = buffer->data();
  for (int i = 0; i < plain2->size; i++) {
    *p = plain2->buffer[i];
    ++p;
  }
  printf("\nTPMRSADecrypt - Decrypted Output: ");
  for (int v = 0; v < (int) plain2->size; v++) {
    // plain2->buffer[v] = data.bytes()[v];
    printf("%02x ", plain2->buffer[v]);
  }

  printf("------------- TPM_RSA_Decrypt done\n");
  return Status::Success();
}

TPMI_ALG_CIPHER_MODE mode = TPM2_ALG_NULL;
TPM2B_IV ivIn = {
    .size = 16,
    .buffer = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
};
TPM2B_MAX_BUFFER inData = {
    .size = 4,
    .buffer = {'a', 's', 'd', 'f'}
};
TPM2B_IV *ivOut = NULL;
TPM2B_MAX_BUFFER *outData = NULL;

// Dummy Functions
Status TPMEncrypt() {return Status::Success();}

TPM2B_MAX_BUFFER *outData2 = NULL;
TPM2B_IV *ivOut2 = NULL;
Status TPMDecrypt() {return Status::Success();}

// SymEncryptDecrypt tested with AESGCM128 - only available on vTPM
Status TPMDoEncryptOrDecrypt(bool encrypt, const std::vector<uint8_t>& raw_key, const CryptoData& data, 
  unsigned int tag_length_bytes, const CryptoData& iv, const CryptoData& additional_data, const EVP_AEAD* aead_alg, 
  std::vector<uint8_t>* buffer) {
  printf("encrypt: %x\n", encrypt);
  printf("raw_key: %02x\n", raw_key[0]);
  printf("data byte length: %02x\n", data.byte_length());
  printf("data: %2s\n", data.bytes());
  printf("tag_length_bytes: %02x\n", tag_length_bytes);
  printf("additional_data byte length: %02x\n", additional_data.byte_length());
  printf("additional_data: %2s\n", additional_data.bytes());

  if (esys_context == NULL) {
    printf("\n------------- TPMEncrypt ctx was null\n");
    TPMInit();
  }
  if (primaryHandle == ESYS_TR_NONE) {
    TPMCreatePrimary();
  }
  if (encrypt) {
    // TPMCreate();
    printf("\n------------- TPMEncrypt\n");
    TPMI_YES_NO encrypt = TPM2_NO;
    ESYS_TR keyHandle_handle = loadedKeyHandle;
    // ivIn.size = iv.byte_length();
    // for (int v = 0; v < (int) ivIn.size; v++) {
    //   ivIn.buffer[v] = iv.bytes()[v];
    // }
    printf("iv byte length: %02x", iv.byte_length());
    printf("iv: %2s ", iv.bytes());
    inData.size = data.byte_length();
    for (int v = 0; v < (int) inData.size; v++) {
      inData.buffer[v] = data.bytes()[v];
    }
    TSS2_RC(*Esys_EncryptDecrypt)(ESYS_CONTEXT*, ESYS_TR, ESYS_TR, ESYS_TR, ESYS_TR, 
    TPMI_YES_NO, TPMI_ALG_CIPHER_MODE, const TPM2B_IV *, const TPM2B_MAX_BUFFER *, 
    TPM2B_MAX_BUFFER **, TPM2B_IV **) =
      (TSS2_RC(*)(ESYS_CONTEXT*, ESYS_TR, ESYS_TR, ESYS_TR, ESYS_TR, 
    TPMI_YES_NO, TPMI_ALG_CIPHER_MODE, const TPM2B_IV *, const TPM2B_MAX_BUFFER *, 
    TPM2B_MAX_BUFFER **, TPM2B_IV **))dlsym(handle, "Esys_EncryptDecrypt");
    r = Esys_EncryptDecrypt(
        esys_context,
        keyHandle_handle,
        ESYS_TR_PASSWORD,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        encrypt,
        mode,
        &ivIn,
        &inData,
        &outData,
        &ivOut);

    if (r != TSS2_RC_SUCCESS) {
      printf("\nError in Esys_EncryptDecrypt\nError:%s\n",
              strerror(errno));
      abort();
    }
    printf("\n------------- inData\n");
    for (int v = 0; v < (int) inData.size; v++)
    {
      printf("%02x ", inData.buffer[v]);
    }
    printf("\n------------- outData\n");
    for (int v = 0; v < (int) outData->size; v++)
    {
      printf("%02x ", outData->buffer[v]);
    }
    printf("------------- TPMEncrypt done\n");
    buffer->resize(outData->size);
    uint8_t* p = buffer->data();
    for (int i = 0; i < outData->size; i++) {
      *p = outData->buffer[i];
      ++p;
      // printf("0x%x ", outData2->buffer[i]);
    }
    return Status::Success();

  } else {  // Decrypt

    printf("------------- TPMDecrypt\n");
    TPMI_YES_NO decrypt = TPM2_YES;
    //TPMI_YES_NO encrypt = TPM2_NO;
    ESYS_TR keyHandle_handle = loadedKeyHandle;
    /*
    TSS2_RC Esys_EncryptDecrypt 	( 	ESYS_CONTEXT *  	esysContext,
      ESYS_TR  	keyHandle,
      ESYS_TR  	shandle1,
      ESYS_TR  	shandle2,
      ESYS_TR  	shandle3,
      TPMI_YES_NO  	decrypt,
      TPMI_ALG_CIPHER_MODE  	mode,
      const TPM2B_IV *  	ivIn,
      const TPM2B_MAX_BUFFER *  	inData,
      TPM2B_MAX_BUFFER **  	outData,
      TPM2B_IV **  	ivOut 
    ) 	
    */
    TSS2_RC(*Esys_EncryptDecrypt)(ESYS_CONTEXT*, ESYS_TR, ESYS_TR, ESYS_TR, ESYS_TR, 
    TPMI_YES_NO, TPMI_ALG_CIPHER_MODE, const TPM2B_IV *, const TPM2B_MAX_BUFFER *, 
    TPM2B_MAX_BUFFER **, TPM2B_IV **) =
      (TSS2_RC(*)(ESYS_CONTEXT*, ESYS_TR, ESYS_TR, ESYS_TR, ESYS_TR, 
    TPMI_YES_NO, TPMI_ALG_CIPHER_MODE, const TPM2B_IV *, const TPM2B_MAX_BUFFER *, 
    TPM2B_MAX_BUFFER **, TPM2B_IV **))dlsym(handle, "Esys_EncryptDecrypt");
    r = Esys_EncryptDecrypt(esys_context, keyHandle_handle, ESYS_TR_PASSWORD,
        ESYS_TR_NONE, ESYS_TR_NONE, decrypt, mode, &ivIn, outData, &outData2, &ivOut2);

    if (r != TSS2_RC_SUCCESS) {
      printf("\nError in Esys_EncryptDecrypt - Decrypt\nError:%s\n",
              strerror(errno));
      abort();
    }

    buffer->resize(outData2->size);
    uint8_t* p = buffer->data();
    for (int i = 0; i < outData2->size; i++) {
      *p = outData2->buffer[i];
      ++p;
      // printf("0x%x ", outData2->buffer[i]);
    }

    printf("\n------------- inData\n");
    for (int v = 0; v < (int) outData->size; v++)
    {
      printf("%02x ", outData->buffer[v]);
    }
    printf("\n------------- outData\n");
    for (int v = 0; v < (int) outData2->size; v++)
    {
      printf("%02x ", outData2->buffer[v]);
    }
    printf("------------- TPMDecrypt done\n");
    return Status::Success();
  }
}

TPMT_SIGNATURE *sig = NULL;
TPM2B_DIGEST digest = { .size = SHA256_DIGEST_LENGTH,
  .buffer = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,11, 12, 13, 14, 15, 16, 17,
                18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32} }; // boringssl/.../sha.ha

Status TPMRSASign(const blink::WebCryptoKey& key, const CryptoData& data, std::vector<uint8_t>* buffer) {
  printf("------------- Sign\n");
  if (esys_context == NULL) {
    printf("\n------------- TPMEncrypt ctx was null\n");
    TPMInit();
  }
  if (primaryHandle == ESYS_TR_NONE) {
    TPMCreatePrimarySignVerify();
  }
  TPMT_SIG_SCHEME inScheme = {.scheme = TPM2_ALG_NULL}; // = TPM2_ALG_NULL
  TPMT_TK_HASHCHECK hash_validation = { .tag = TPM2_ST_HASHCHECK,
                                    .hierarchy = TPM2_RH_OWNER, // TPM2_RH_NULL || TPM2_RH_OWNER
                                    .digest = {0}};

  TSS2_RC(*Esys_Sign)
  (ESYS_CONTEXT*, ESYS_TR, ESYS_TR, ESYS_TR, ESYS_TR,
    const TPM2B_DIGEST*, const TPMT_SIG_SCHEME*, const TPMT_TK_HASHCHECK*,
  TPMT_SIGNATURE**) =
  (TSS2_RC(*)(ESYS_CONTEXT*, ESYS_TR, ESYS_TR, ESYS_TR, ESYS_TR,
    const TPM2B_DIGEST*, const TPMT_SIG_SCHEME*, const TPMT_TK_HASHCHECK*,
  TPMT_SIGNATURE**))dlsym(handle, "Esys_Sign");

  r = (*Esys_Sign)(esys_context, primaryHandle, ESYS_TR_PASSWORD, ESYS_TR_NONE,
                            ESYS_TR_NONE, &digest, &inScheme,
                            &hash_validation, &sig);

  if (r != TSS2_RC_SUCCESS) {
    printf("\nError in Esys_Sign\nError:%s\n",
            strerror(errno));
    abort();
  }

  printf("\nTPMSign Signature: ");
  buffer->resize(sig->signature.rsapss.sig.size);
  uint8_t* p = buffer->data();
  for (int i = 0; i < sig->signature.rsapss.sig.size; i++) {
    *p = sig->signature.rsapss.sig.buffer[i];
    ++p;
    printf("0x%x ", sig->signature.rsapss.sig.buffer[i]);
  }
  printf("\n");

  return Status::Success();
}

Status TPMRSAVerify(const blink::WebCryptoKey& key, const CryptoData& signature,
                    const CryptoData& data, bool* signature_match) {
  printf("------------- Verify\n");
  TPMT_TK_VERIFIED *validation = NULL;

  // printf("\nTPMSign Verify: ");
  // signature.byte_length() = sig->signature.rsapss.sig.size
  // for (int i = 0; i < sig->signature.rsapss.sig.size; i++) {
  //   sig->signature.rsapss.sig.buffer[i] = signature.bytes()[i];
  //   printf("0x%x ", sig->signature.rsapss.sig.buffer[i]);
  // }
  // printf("\n");

  /*TSS2_RC Esys_VerifySignature 	( 	ESYS_CONTEXT *  	esysContext,
  ESYS_TR  	keyHandle,
  ESYS_TR  	shandle1,
  ESYS_TR  	shandle2,
  ESYS_TR  	shandle3,
  const TPM2B_DIGEST *  	digest,
  const TPMT_SIGNATURE *  	signature,
  TPMT_TK_VERIFIED **  	validation 
  ) 	*/
  TSS2_RC(*Esys_VerifySignature) (ESYS_CONTEXT *, ESYS_TR, ESYS_TR, ESYS_TR, ESYS_TR, 
  const TPM2B_DIGEST *, const TPMT_SIGNATURE *, TPMT_TK_VERIFIED **) = 
  (TSS2_RC(*)(ESYS_CONTEXT *, ESYS_TR, ESYS_TR, ESYS_TR, ESYS_TR, 
  const TPM2B_DIGEST *, const TPMT_SIGNATURE *, TPMT_TK_VERIFIED **))dlsym(handle, "Esys_VerifySignature");

  r = (*Esys_VerifySignature)(esys_context, primaryHandle, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &digest, sig, &validation);

  if (r != TSS2_RC_SUCCESS) {
    printf("\nError in Esys_Verify\nError:%s\n",
            strerror(errno));
    abort();
  }
  printf("------------- Verify done\n");
  *signature_match = true;
  return Status::Success();
}

// Dummy Functions
Status TPMSign() {return Status::Success();}

Status TPMVerify() {return Status::Success();}

Status TPMFlushContext() {
  /*TSS2_RC Esys_FlushContext 	( 	ESYS_CONTEXT *  	esysContext,
      ESYS_TR  	flushHandle 
    ) 	*/
  TSS2_RC(*Esys_FlushContext) (ESYS_CONTEXT *, ESYS_TR) = 
  (TSS2_RC(*)(ESYS_CONTEXT *, ESYS_TR))dlsym(handle, "Esys_FlushContext");
  printf("------------- FlushContext\n");
  r = Esys_FlushContext(esys_context, loadedKeyHandle);

  if (r != TSS2_RC_SUCCESS) {
    printf("\nError in FlushContext\nError:%s\n",
            strerror(errno));
    abort();
  }
  loadedKeyHandle = ESYS_TR_NONE;
  printf("------------- FlushContext done\n");
  return Status::Success();
}

Status TPMImport(blink::WebCryptoKeyFormat format,
                    const CryptoData& key_data,
                    const blink::WebCryptoAlgorithm& algorithm,
                    bool extractable,
                    blink::WebCryptoKeyUsageMask usages,
                    blink::WebCryptoKey* key) {

    // TSS2_RC r;
    // TSS2_TCTI_CONTEXT *tcti;
    // ESYS_CONTEXT *esys_context = (ESYS_CONTEXT *) * state; 
    // Esys_GetTcti(esys_context, &tcti);
  if (esys_context == NULL) {
    printf("\n------------- TPMImport ctx was null\n");
    TPMInit();
  }
  if (primaryHandle == ESYS_TR_NONE) {
    // TPMCreatePrimarySignVerify();
  }
    ESYS_TR parentHandle_handle = DUMMY_TR_HANDLE_KEY;
    TPM2B_DATA encryptionKey = DUMMY_2B_DATA;
    TPM2B_PRIVATE duplicate = DUMMY_2B_DATA;
    size_t plain_size = key_data.byte_length();
    // printf("\eimported keydata: ");
    // for (int v = 0; v < (int) plain_size; v++) {
    //   encryptionKey.buffer[v] = key_data.bytes()[v];
    //   duplicate.buffer[v] = key_data.bytes()[v];
    //   printf("%02x ", encryptionKey.buffer[v]);
    // }
    // printf("\n");
    TPM2B_ENCRYPTED_SECRET inSymSeed = DUMMY_2B_SECRET;
    TPM2B_PUBLIC objectPublic = DUMMY_IN_PUBLIC_DATA;
    TPMT_SYM_DEF_OBJECT symmetricAlg = DUMMY_SYMMETRIC;
    TPM2B_PRIVATE *outPrivate;
  /*
    Esys_Import (ESYS_CONTEXT *esysContext, ESYS_TR parentHandle, ESYS_TR shandle1, ESYS_TR shandle2, ESYS_TR shandle3, 
                const TPM2B_DATA *encryptionKey, const TPM2B_PUBLIC *objectPublic, const TPM2B_PRIVATE *duplicate, 
                const TPM2B_ENCRYPTED_SECRET *inSymSeed, const TPMT_SYM_DEF_OBJECT *symmetricAlg, TPM2B_PRIVATE **outPrivate)
  */
   TSS2_RC(*Esys_Import)(ESYS_CONTEXT *, ESYS_TR, ESYS_TR, ESYS_TR, ESYS_TR, const TPM2B_DATA*, const TPM2B_PUBLIC*, 
    const TPM2B_PRIVATE*, const TPM2B_ENCRYPTED_SECRET*, const TPMT_SYM_DEF_OBJECT*, TPM2B_PRIVATE**) = 
  (TSS2_RC(*)(ESYS_CONTEXT *, ESYS_TR, ESYS_TR, ESYS_TR, ESYS_TR, const TPM2B_DATA*, const TPM2B_PUBLIC*, 
    const TPM2B_PRIVATE*, const TPM2B_ENCRYPTED_SECRET*, const TPMT_SYM_DEF_OBJECT*, TPM2B_PRIVATE**))dlsym(handle, "Esys_Import");
  r = Esys_Import(esys_context,
                  parentHandle_handle,
                  ESYS_TR_PASSWORD,
                  ESYS_TR_NONE,
                  ESYS_TR_NONE,
                  &encryptionKey,
                  &objectPublic,
                  &duplicate, &inSymSeed, &symmetricAlg, &outPrivate);
  printf("------------- TPMImport done\n");
  return Status::Success();
}

Status TPMExport(blink::WebCryptoKeyFormat format,
                    const blink::WebCryptoKey& key,
                    std::vector<uint8_t>* buffer) {
  TPMWritePublicKey(buffer);
  printf("------------- TPMExport done\n");
  return Status::Success();
}

Status TPMWritePublicKey(std::vector<uint8_t>* pk) {
  pk->resize(outPublic->publicArea.unique.keyedHash.size);
  uint8_t* p = pk->data();
  for (int i = 0; i < outPublic->publicArea.unique.keyedHash.size; i++) {
    *p = outPublic->publicArea.unique.keyedHash.buffer[i];
    ++p;
  }
  printf("------------- TPMWritePublicKey done\n");
  return Status::Success();
}

// ---------------------------------------------------------------------------------------------

Status GenerateKey(const blink::WebCryptoAlgorithm& algorithm,
                   bool extractable,
                   blink::WebCryptoKeyUsageMask usages,
                   GenerateKeyResult* result) {
  const AlgorithmImplementation* impl = nullptr;
  Status status = GetAlgorithmImplementation(algorithm.Id(), &impl);
  if (status.IsError())
    return status;

  status = impl->GenerateKey(algorithm, extractable, usages, result);
  if (status.IsError())
    return status;

  // The Web Crypto spec says to reject secret and private keys generated with
  // empty usages:
  //
  // https://w3c.github.io/webcrypto/Overview.html#dfn-SubtleCrypto-method-generateKey
  //
  // (14.3.6.8):
  // If result is a CryptoKey object:
  //     If the [[type]] internal slot of result is "secret" or "private"
  //     and usages is empty, then throw a SyntaxError.
  //
  // (14.3.6.9)
  // If result is a CryptoKeyPair object:
  //     If the [[usages]] internal slot of the privateKey attribute of
  //     result is the empty sequence, then throw a SyntaxError.
  const blink::WebCryptoKey* key = nullptr;
  if (result->type() == GenerateKeyResult::TYPE_SECRET_KEY)
    key = &result->secret_key();
  if (result->type() == GenerateKeyResult::TYPE_PUBLIC_PRIVATE_KEY_PAIR)
    key = &result->private_key();
  if (key == nullptr)
    return Status::ErrorUnexpected();

  if (key->Usages() == 0) {
    return Status::ErrorCreateKeyEmptyUsages();
  }

  // Key k = dynamic_cast<blink::Key*>(key->Handle());
  printf("WCA - GenerateKey \n");
  // printf("%02x ", GetSerializedKeyData(*key)[0]);
  return Status::Success();
}

Status ImportKey(blink::WebCryptoKeyFormat format,
                 const CryptoData& key_data,
                 const blink::WebCryptoAlgorithm& algorithm,
                 bool extractable,
                 blink::WebCryptoKeyUsageMask usages,
                 blink::WebCryptoKey* key) {
  const AlgorithmImplementation* impl = nullptr;
  Status status = GetAlgorithmImplementation(algorithm.Id(), &impl);
  if (status.IsError())
    return status;

  status =
      impl->ImportKey(format, key_data, algorithm, extractable, usages, key);
  if (status.IsError())
    return status;

  // The Web Crypto spec says to reject secret and private keys imported with
  // empty usages:
  //
  // https://w3c.github.io/webcrypto/Overview.html#dfn-SubtleCrypto-method-importKey
  //
  // 14.3.9.9: If the [[type]] internal slot of result is "secret" or "private"
  //           and usages is empty, then throw a SyntaxError.
  if (key->Usages() == 0 &&
      (key->GetType() == blink::kWebCryptoKeyTypeSecret ||
       key->GetType() == blink::kWebCryptoKeyTypePrivate)) {
    return Status::ErrorCreateKeyEmptyUsages();
  }
  printf("WCA - ImportKey \n");
  return Status::Success();
}

Status ExportKey(blink::WebCryptoKeyFormat format,
                 const blink::WebCryptoKey& key,
                 std::vector<uint8_t>* buffer) {
  printf("WCA - ExportKey \n");
  if (!key.Extractable())
    return Status::ErrorKeyNotExtractable();
  return ExportKeyDontCheckExtractability(format, key, buffer);
}

Status Sign(const blink::WebCryptoAlgorithm& algorithm,
            const blink::WebCryptoKey& key,
            const CryptoData& data,
            std::vector<uint8_t>* buffer) {
  if (!key.KeyUsageAllows(blink::kWebCryptoKeyUsageSign))
    return Status::ErrorUnexpected();
  if (algorithm.Id() != key.Algorithm().Id())
    return Status::ErrorUnexpected();

  const AlgorithmImplementation* impl = nullptr;
  Status status = GetAlgorithmImplementation(algorithm.Id(), &impl);
  if (status.IsError())
    return status;

  printf("WCA - Sign \n");
  return impl->Sign(algorithm, key, data, buffer);
}

Status Verify(const blink::WebCryptoAlgorithm& algorithm,
              const blink::WebCryptoKey& key,
              const CryptoData& signature,
              const CryptoData& data,
              bool* signature_match) {
  if (!key.KeyUsageAllows(blink::kWebCryptoKeyUsageVerify))
    return Status::ErrorUnexpected();
  if (algorithm.Id() != key.Algorithm().Id())
    return Status::ErrorUnexpected();

  const AlgorithmImplementation* impl = nullptr;
  Status status = GetAlgorithmImplementation(algorithm.Id(), &impl);
  if (status.IsError())
    return status;

  printf("WCA - Verify \n");
  return impl->Verify(algorithm, key, signature, data, signature_match);
}

Status WrapKey(blink::WebCryptoKeyFormat format,
               const blink::WebCryptoKey& key_to_wrap,
               const blink::WebCryptoKey& wrapping_key,
               const blink::WebCryptoAlgorithm& wrapping_algorithm,
               std::vector<uint8_t>* buffer) {
  if (!wrapping_key.KeyUsageAllows(blink::kWebCryptoKeyUsageWrapKey))
    return Status::ErrorUnexpected();

  std::vector<uint8_t> exported_data;
  Status status = ExportKey(format, key_to_wrap, &exported_data);
  printf("WCA - WrapKey \n");
  if (status.IsError())
    return status;
  return EncryptDontCheckUsage(wrapping_algorithm, wrapping_key,
                               CryptoData(exported_data), buffer);
}

Status UnwrapKey(blink::WebCryptoKeyFormat format,
                 const CryptoData& wrapped_key_data,
                 const blink::WebCryptoKey& wrapping_key,
                 const blink::WebCryptoAlgorithm& wrapping_algorithm,
                 const blink::WebCryptoAlgorithm& algorithm,
                 bool extractable,
                 blink::WebCryptoKeyUsageMask usages,
                 blink::WebCryptoKey* key) {
  printf("WCA - UnwrapKey \n");
  if (!wrapping_key.KeyUsageAllows(blink::kWebCryptoKeyUsageUnwrapKey))
    return Status::ErrorUnexpected();
  if (wrapping_algorithm.Id() != wrapping_key.Algorithm().Id())
    return Status::ErrorUnexpected();

  std::vector<uint8_t> buffer;
  Status status = DecryptDontCheckKeyUsage(wrapping_algorithm, wrapping_key,
                                           wrapped_key_data, &buffer);
  if (status.IsError())
    return status;

  // NOTE that returning the details of ImportKey() failures may leak
  // information about the plaintext of the encrypted key (for instance the JWK
  // key_ops). As long as the ImportKey error messages don't describe actual
  // key bytes however this should be OK. For more discussion see
  // http://crbug.com/372040
  return ImportKey(format, CryptoData(buffer), algorithm, extractable, usages,
                   key);
}

Status DeriveBits(const blink::WebCryptoAlgorithm& algorithm,
                  const blink::WebCryptoKey& base_key,
                  unsigned int length_bits,
                  std::vector<uint8_t>* derived_bytes) {
  if (!base_key.KeyUsageAllows(blink::kWebCryptoKeyUsageDeriveBits))
    return Status::ErrorUnexpected();

  if (algorithm.Id() != base_key.Algorithm().Id())
    return Status::ErrorUnexpected();

  const AlgorithmImplementation* impl = nullptr;
  Status status = GetAlgorithmImplementation(algorithm.Id(), &impl);
  if (status.IsError())
    return status;

  printf("WCA - DeriveBits \n");
  return impl->DeriveBits(algorithm, base_key, true, length_bits,
                          derived_bytes);
}

Status DeriveKey(const blink::WebCryptoAlgorithm& algorithm,
                 const blink::WebCryptoKey& base_key,
                 const blink::WebCryptoAlgorithm& import_algorithm,
                 const blink::WebCryptoAlgorithm& key_length_algorithm,
                 bool extractable,
                 blink::WebCryptoKeyUsageMask usages,
                 blink::WebCryptoKey* derived_key) {
  printf("WCA - DeriveKey \n");
  if (!base_key.KeyUsageAllows(blink::kWebCryptoKeyUsageDeriveKey))
    return Status::ErrorUnexpected();

  if (algorithm.Id() != base_key.Algorithm().Id())
    return Status::ErrorUnexpected();

  if (import_algorithm.Id() != key_length_algorithm.Id())
    return Status::ErrorUnexpected();

  const AlgorithmImplementation* import_impl = nullptr;
  Status status =
      GetAlgorithmImplementation(import_algorithm.Id(), &import_impl);
  if (status.IsError())
    return status;

  // Determine how many bits long the derived key should be.
  unsigned int length_bits = 0;
  bool has_length_bits = false;
  status = import_impl->GetKeyLength(key_length_algorithm, &has_length_bits,
                                     &length_bits);
  if (status.IsError())
    return status;

  // Derive the key bytes.
  const AlgorithmImplementation* derive_impl = nullptr;
  status = GetAlgorithmImplementation(algorithm.Id(), &derive_impl);
  if (status.IsError())
    return status;

  std::vector<uint8_t> derived_bytes;
  status = derive_impl->DeriveBits(algorithm, base_key, has_length_bits,
                                   length_bits, &derived_bytes);
  if (status.IsError())
    return status;

  // Create the key using the derived bytes.
  return ImportKey(blink::kWebCryptoKeyFormatRaw, CryptoData(derived_bytes),
                   import_algorithm, extractable, usages, derived_key);
}

bool SerializeKeyForClone(const blink::WebCryptoKey& key,
                          blink::WebVector<uint8_t>* key_data) {
  const AlgorithmImplementation* impl = nullptr;
  Status status = GetAlgorithmImplementation(key.Algorithm().Id(), &impl);
  printf("WCA - SerializeKeyForClone \n");
  if (status.IsError())
    return false;

  status = impl->SerializeKeyForClone(key, key_data);
  return status.IsSuccess();
}

bool DeserializeKeyForClone(const blink::WebCryptoKeyAlgorithm& algorithm,
                            blink::WebCryptoKeyType type,
                            bool extractable,
                            blink::WebCryptoKeyUsageMask usages,
                            const CryptoData& key_data,
                            blink::WebCryptoKey* key) {
  const AlgorithmImplementation* impl = nullptr;
  printf("WCA - DeserializeKeyForClone \n");
  Status status = GetAlgorithmImplementation(algorithm.Id(), &impl);
  if (status.IsError())
    return false;

  status = impl->DeserializeKeyForClone(algorithm, type, extractable, usages,
                                        key_data, key);
  return status.IsSuccess();
}

}  // namespace webcrypto
