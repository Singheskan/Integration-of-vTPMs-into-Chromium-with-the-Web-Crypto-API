/*
 * Copyright (C) 2013 Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *     * Neither the name of Google Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef THIRD_PARTY_BLINK_RENDERER_MODULES_CRYPTO_SUBTLE_CRYPTO_H_
#define THIRD_PARTY_BLINK_RENDERER_MODULES_CRYPTO_SUBTLE_CRYPTO_H_

#include "third_party/blink/renderer/bindings/core/v8/script_promise.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_typedefs.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_typedefs.h"
#include "third_party/blink/renderer/modules/crypto/normalize_algorithm.h"
#include "third_party/blink/renderer/platform/bindings/script_wrappable.h"
#include "third_party/blink/renderer/platform/heap/handle.h"
#include "third_party/blink/renderer/platform/wtf/forward.h"

#include <dlfcn.h>  //dlopen
#include <iostream>
#include "third_party/tpm/tpm2-tss/include/tss2/tss2_common.h"
#include "third_party/tpm/tpm2-tss/include/tss2/tss2_esys.h"
#include "third_party/tpm/tpm2-tss/include/tss2/tss2_fapi.h"
#include "third_party/tpm/tpm2-tss/include/tss2/tss2_rc.h"


#define ENGINE_HASH_ALG TPM2_ALG_SHA256

#define TPM2B_PUBLIC_PRIMARY_RSA_TEMPLATE { \
    .publicArea = { \
        .type = TPM2_ALG_RSA, \
        .nameAlg = ENGINE_HASH_ALG, \
        .objectAttributes = (TPMA_OBJECT_USERWITHAUTH | \
                             TPMA_OBJECT_RESTRICTED | \
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
                 .algorithm = TPM2_ALG_AES, \
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

namespace blink {

class CryptoKey;

class SubtleCrypto final : public ScriptWrappable {
  DEFINE_WRAPPERTYPEINFO();

 public:
  SubtleCrypto();

  ScriptPromise encrypt(ScriptState*,
                        const V8AlgorithmIdentifier*,
                        CryptoKey*,
                        const V8BufferSource*,
                        ExceptionState&);
  ScriptPromise decrypt(ScriptState*,
                        const V8AlgorithmIdentifier*,
                        CryptoKey*,
                        const V8BufferSource*,
                        ExceptionState&);
  ScriptPromise sign(ScriptState*,
                     const V8AlgorithmIdentifier*,
                     CryptoKey*,
                     const V8BufferSource*,
                     ExceptionState&);
  // Note that this is not named "verify" because when compiling on Mac that
  // expands to a macro and breaks.
  ScriptPromise verifySignature(ScriptState*,
                                const V8AlgorithmIdentifier*,
                                CryptoKey*,
                                const V8BufferSource* signature,
                                const V8BufferSource* data,
                                ExceptionState&);
  ScriptPromise digest(ScriptState*,
                       const V8AlgorithmIdentifier*,
                       const V8BufferSource* data,
                       ExceptionState&);

  ScriptPromise generateKey(ScriptState*,
                            const V8AlgorithmIdentifier*,
                            bool extractable,
                            const Vector<String>& key_usages,
                            ExceptionState&);
  ScriptPromise importKey(ScriptState*,
                          const String&,
                          const V8UnionBufferSourceOrJsonWebKey*,
                          const V8AlgorithmIdentifier*,
                          bool extractable,
                          const Vector<String>& key_usages,
                          ExceptionState&);
  ScriptPromise exportKey(ScriptState*, const String&, CryptoKey*);

  ScriptPromise wrapKey(ScriptState*,
                        const String&,
                        CryptoKey*,
                        CryptoKey*,
                        const V8AlgorithmIdentifier*,
                        ExceptionState&);
  ScriptPromise unwrapKey(ScriptState*,
                          const String&,
                          const V8BufferSource*,
                          CryptoKey*,
                          const V8AlgorithmIdentifier*,
                          const V8AlgorithmIdentifier*,
                          bool,
                          const Vector<String>&,
                          ExceptionState&);

  ScriptPromise deriveBits(ScriptState*,
                           const V8AlgorithmIdentifier*,
                           CryptoKey*,
                           unsigned,
                           ExceptionState&);
  ScriptPromise deriveKey(ScriptState*,
                          const V8AlgorithmIdentifier*,
                          CryptoKey*,
                          const V8AlgorithmIdentifier*,
                          bool extractable,
                          const Vector<String>&,
                          ExceptionState&);
};

}  // namespace blink

#endif  // THIRD_PARTY_BLINK_RENDERER_MODULES_CRYPTO_SUBTLE_CRYPTO_H_
