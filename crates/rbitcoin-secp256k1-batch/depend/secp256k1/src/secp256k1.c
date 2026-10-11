/***********************************************************************
 * Copyright (c) 2013-2015 Pieter Wuille                               *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

/* This is a C project. It should not be compiled with a C++ compiler,
 * and we error out if we detect one.
 *
 * We still want to be able to test the project with a C++ compiler
 * because it is still good to know if this will lead to real trouble, so
 * there is a possibility to override the check. But be warned that
 * compiling with a C++ compiler is not supported. */
#if defined(__cplusplus) && !defined(SECP256K1_CPLUSPLUS_TEST_OVERRIDE)
#error Trying to compile a C project with a C++ compiler.
#endif

#define SECP256K1_BUILD

#include "../include/secp256k1.h"
#include "../include/secp256k1_preallocated.h"

#include "assumptions.h"
#include "checkmem.h"
#include "util.h"

#include "field_impl.h"
#include "scalar_impl.h"
#include "group_impl.h"
#include "ecmult_impl.h"
#include "ecmult_const_impl.h"
#include "ecmult_gen_impl.h"
#include "ecdsa_impl.h"
#include "eckey_impl.h"
#include "hash_impl.h"
#include "int128_impl.h"
#include "scratch_impl.h"
#include "selftest.h"
#include "hsort_impl.h"

#ifdef SECP256K1_NO_BUILD
# error "secp256k1.h processed without SECP256K1_BUILD defined while building secp256k1.c"
#endif

#define ARG_CHECK(cond) do { \
    if (EXPECT(!(cond), 0)) { \
        rbtc_secp256k1_callback_call(&ctx->illegal_callback, #cond); \
        return 0; \
    } \
} while(0)

#define ARG_CHECK_VOID(cond) do { \
    if (EXPECT(!(cond), 0)) { \
        rbtc_secp256k1_callback_call(&ctx->illegal_callback, #cond); \
        return; \
    } \
} while(0)

/* Note that whenever you change the context struct, you must also change the
 * context_eq function. */
struct rbtc_secp256k1_context_struct {
    rbtc_secp256k1_ecmult_gen_context ecmult_gen_ctx;
    rbtc_secp256k1_hash_ctx hash_ctx;
    rbtc_secp256k1_callback illegal_callback;
    rbtc_secp256k1_callback error_callback;
    int declassify;
};

static const rbtc_secp256k1_context rbtc_secp256k1_context_static_ = {
    { 0 },
    { rbtc_secp256k1_sha256_transform },
    { rbtc_secp256k1_default_illegal_callback_fn, 0 },
    { rbtc_secp256k1_default_error_callback_fn, 0 },
    0
};
const rbtc_secp256k1_context * const rbtc_secp256k1_context_static = &rbtc_secp256k1_context_static_;
const rbtc_secp256k1_context * const rbtc_secp256k1_context_no_precomp = &rbtc_secp256k1_context_static_;

/* Helper function that determines if a context is proper, i.e., is not the static context or a copy thereof.
 *
 * This is intended for "context" functions such as rbtc_secp256k1_context_clone. Functions that need specific
 * features of a context should still check for these features directly. For example, a function that needs
 * ecmult_gen should directly check for the existence of the ecmult_gen context. */
static int rbtc_secp256k1_context_is_proper(const rbtc_secp256k1_context* ctx) {
    return rbtc_secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx);
}

void rbtc_secp256k1_selftest(void) {
    if (!rbtc_secp256k1_selftest_passes()) {
        rbtc_secp256k1_callback_call(&default_error_callback, "self test failed");
    }
}

size_t rbtc_secp256k1_context_preallocated_size(unsigned int flags) {
    size_t ret = sizeof(rbtc_secp256k1_context);
    /* A return value of 0 is reserved as an indicator for errors when we call this function internally. */
    VERIFY_CHECK(ret != 0);

    if (EXPECT((flags & SECP256K1_FLAGS_TYPE_MASK) != SECP256K1_FLAGS_TYPE_CONTEXT, 0)) {
            rbtc_secp256k1_callback_call(&default_illegal_callback,
                                    "Invalid flags");
            return 0;
    }

    if (EXPECT(!SECP256K1_CHECKMEM_RUNNING() && (flags & SECP256K1_FLAGS_BIT_CONTEXT_DECLASSIFY), 0)) {
            rbtc_secp256k1_callback_call(&default_illegal_callback,
                                    "Declassify flag requires running with memory checking");
            return 0;
    }

    return ret;
}

size_t rbtc_secp256k1_context_preallocated_clone_size(const rbtc_secp256k1_context* ctx) {
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(rbtc_secp256k1_context_is_proper(ctx));
    return sizeof(rbtc_secp256k1_context);
}

rbtc_secp256k1_context* rbtc_secp256k1_context_preallocated_create(void* prealloc, unsigned int flags) {
    size_t prealloc_size;
    rbtc_secp256k1_context* ret;

    rbtc_secp256k1_selftest();

    prealloc_size = rbtc_secp256k1_context_preallocated_size(flags);
    if (prealloc_size == 0) {
        return NULL;
    }
    VERIFY_CHECK(prealloc != NULL);
    ret = (rbtc_secp256k1_context*)prealloc;
    ret->illegal_callback = default_illegal_callback;
    ret->error_callback = default_error_callback;
    rbtc_secp256k1_hash_ctx_init(&ret->hash_ctx);

    /* Flags have been checked by rbtc_secp256k1_context_preallocated_size. */
    VERIFY_CHECK((flags & SECP256K1_FLAGS_TYPE_MASK) == SECP256K1_FLAGS_TYPE_CONTEXT);
    rbtc_secp256k1_ecmult_gen_context_build(&ret->ecmult_gen_ctx, &ret->hash_ctx);
    ret->declassify = !!(flags & SECP256K1_FLAGS_BIT_CONTEXT_DECLASSIFY);

    return ret;
}

rbtc_secp256k1_context* rbtc_secp256k1_context_create(unsigned int flags) {
    size_t const prealloc_size = rbtc_secp256k1_context_preallocated_size(flags);
    rbtc_secp256k1_context* ctx = checked_malloc(&default_error_callback, prealloc_size);
    if (EXPECT(rbtc_secp256k1_context_preallocated_create(ctx, flags) == NULL, 0)) {
        free(ctx);
        return NULL;
    }

    return ctx;
}

rbtc_secp256k1_context* rbtc_secp256k1_context_preallocated_clone(const rbtc_secp256k1_context* ctx, void* prealloc) {
    rbtc_secp256k1_context* ret;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(prealloc != NULL);
    ARG_CHECK(rbtc_secp256k1_context_is_proper(ctx));

    ret = (rbtc_secp256k1_context*)prealloc;
    *ret = *ctx;
    return ret;
}

rbtc_secp256k1_context* rbtc_secp256k1_context_clone(const rbtc_secp256k1_context* ctx) {
    rbtc_secp256k1_context* ret;
    size_t prealloc_size;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(rbtc_secp256k1_context_is_proper(ctx));

    prealloc_size = rbtc_secp256k1_context_preallocated_clone_size(ctx);
    ret = checked_malloc(&ctx->error_callback, prealloc_size);
    ret = rbtc_secp256k1_context_preallocated_clone(ctx, ret);
    return ret;
}

void rbtc_secp256k1_context_preallocated_destroy(rbtc_secp256k1_context* ctx) {
    ARG_CHECK_VOID(ctx == NULL || rbtc_secp256k1_context_is_proper(ctx));

    /* Defined as noop */
    if (ctx == NULL) {
        return;
    }

    rbtc_secp256k1_ecmult_gen_context_clear(&ctx->ecmult_gen_ctx);
}

void rbtc_secp256k1_context_destroy(rbtc_secp256k1_context* ctx) {
    ARG_CHECK_VOID(ctx == NULL || rbtc_secp256k1_context_is_proper(ctx));

    /* Defined as noop */
    if (ctx == NULL) {
        return;
    }

    rbtc_secp256k1_context_preallocated_destroy(ctx);
    free(ctx);
}

void rbtc_secp256k1_context_set_illegal_callback(rbtc_secp256k1_context* ctx, void (*fun)(const char* message, void* data), const void* data) {
    /* We compare pointers instead of checking rbtc_secp256k1_context_is_proper() here
       because setting callbacks is allowed on *copies* of the static context:
       it's harmless and makes testing easier. */
    ARG_CHECK_VOID(ctx != rbtc_secp256k1_context_static);
    if (fun == NULL) {
        fun = rbtc_secp256k1_default_illegal_callback_fn;
    }
    ctx->illegal_callback.fn = fun;
    ctx->illegal_callback.data = data;
}

void rbtc_secp256k1_context_set_error_callback(rbtc_secp256k1_context* ctx, void (*fun)(const char* message, void* data), const void* data) {
    /* We compare pointers instead of checking rbtc_secp256k1_context_is_proper() here
       because setting callbacks is allowed on *copies* of the static context:
       it's harmless and makes testing easier. */
    ARG_CHECK_VOID(ctx != rbtc_secp256k1_context_static);
    if (fun == NULL) {
        fun = rbtc_secp256k1_default_error_callback_fn;
    }
    ctx->error_callback.fn = fun;
    ctx->error_callback.data = data;
}

void rbtc_secp256k1_context_set_sha256_compression(rbtc_secp256k1_context *ctx, rbtc_secp256k1_sha256_compression_function fn_compression) {
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK_VOID(rbtc_secp256k1_context_is_proper(ctx));
    if (!fn_compression) { /* Reset hash context */
        rbtc_secp256k1_hash_ctx_init(&ctx->hash_ctx);
        return;
    }
    /* Check and set */
    ARG_CHECK_VOID(rbtc_secp256k1_selftest_sha256(fn_compression));
    ctx->hash_ctx.fn_sha256_compression = fn_compression;
}

static SECP256K1_INLINE const rbtc_secp256k1_hash_ctx* rbtc_secp256k1_get_hash_context(const rbtc_secp256k1_context *ctx) {
    return &ctx->hash_ctx;
}

static rbtc_secp256k1_scratch_space* rbtc_secp256k1_scratch_space_create(const rbtc_secp256k1_context* ctx, size_t max_size) {
    VERIFY_CHECK(ctx != NULL);
    return rbtc_secp256k1_scratch_create(&ctx->error_callback, max_size);
}

static void rbtc_secp256k1_scratch_space_destroy(const rbtc_secp256k1_context *ctx, rbtc_secp256k1_scratch_space* scratch) {
    VERIFY_CHECK(ctx != NULL);
    rbtc_secp256k1_scratch_destroy(&ctx->error_callback, scratch);
}

/* Mark memory as no-longer-secret for the purpose of analysing constant-time behaviour
 *  of the software.
 */
static SECP256K1_INLINE void rbtc_secp256k1_declassify(const rbtc_secp256k1_context* ctx, const void *p, size_t len) {
    if (EXPECT(ctx->declassify, 0)) SECP256K1_CHECKMEM_DEFINE(p, len);
}

static int rbtc_secp256k1_pubkey_load(const rbtc_secp256k1_context* ctx, rbtc_secp256k1_ge* ge, const rbtc_secp256k1_pubkey* pubkey) {
    rbtc_secp256k1_ge_from_bytes(ge, pubkey->data);
    ARG_CHECK(!rbtc_secp256k1_fe_is_zero(&ge->x));
    return 1;
}

static void rbtc_secp256k1_pubkey_save(rbtc_secp256k1_pubkey* pubkey, rbtc_secp256k1_ge* ge) {
    rbtc_secp256k1_ge_to_bytes(pubkey->data, ge);
}

int rbtc_secp256k1_ec_pubkey_parse(const rbtc_secp256k1_context* ctx, rbtc_secp256k1_pubkey* pubkey, const unsigned char *input, size_t inputlen) {
    rbtc_secp256k1_ge Q;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(pubkey != NULL);
    memset(pubkey, 0, sizeof(*pubkey));
    ARG_CHECK(input != NULL);
    if (!rbtc_secp256k1_eckey_pubkey_parse(&Q, input, inputlen)) {
        return 0;
    }
    if (!rbtc_secp256k1_ge_is_in_correct_subgroup(&Q)) {
        return 0;
    }
    rbtc_secp256k1_pubkey_save(pubkey, &Q);
    rbtc_secp256k1_ge_clear(&Q);
    return 1;
}

int rbtc_secp256k1_ec_pubkey_serialize(const rbtc_secp256k1_context* ctx, unsigned char *output, size_t *outputlen, const rbtc_secp256k1_pubkey* pubkey, unsigned int flags) {
    rbtc_secp256k1_ge Q;
    size_t len;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(outputlen != NULL);
    ARG_CHECK(*outputlen >= ((flags & SECP256K1_FLAGS_BIT_COMPRESSION) ? 33u : 65u));
    len = *outputlen;
    *outputlen = 0;
    ARG_CHECK(output != NULL);
    memset(output, 0, len);
    ARG_CHECK(pubkey != NULL);
    ARG_CHECK((flags & SECP256K1_FLAGS_TYPE_MASK) == SECP256K1_FLAGS_TYPE_COMPRESSION);
    if (rbtc_secp256k1_pubkey_load(ctx, &Q, pubkey)) {
        if (flags & SECP256K1_FLAGS_BIT_COMPRESSION) {
            rbtc_secp256k1_eckey_pubkey_serialize33(&Q, output);
            *outputlen = 33;
        } else {
            rbtc_secp256k1_eckey_pubkey_serialize65(&Q, output);
            *outputlen = 65;
        }
        return 1;
    }
    return 0;
}

int rbtc_secp256k1_ec_pubkey_cmp(const rbtc_secp256k1_context* ctx, const rbtc_secp256k1_pubkey* pubkey0, const rbtc_secp256k1_pubkey* pubkey1) {
    unsigned char out[2][33];
    const rbtc_secp256k1_pubkey* pk[2];
    int i;

    VERIFY_CHECK(ctx != NULL);
    pk[0] = pubkey0; pk[1] = pubkey1;
    for (i = 0; i < 2; i++) {
        size_t out_size = sizeof(out[i]);
        /* If the public key is NULL or invalid, ec_pubkey_serialize will call
         * the illegal_callback and return 0. In that case we will serialize the
         * key as all zeros which is less than any valid public key. This
         * results in consistent comparisons even if NULL or invalid pubkeys are
         * involved and prevents edge cases such as sorting algorithms that use
         * this function and do not terminate as a result. */
        if (!rbtc_secp256k1_ec_pubkey_serialize(ctx, out[i], &out_size, pk[i], SECP256K1_EC_COMPRESSED)) {
            /* Note that ec_pubkey_serialize should already set the output to
             * zero in that case, but it's not guaranteed by the API, we can't
             * test it and writing a VERIFY_CHECK is more complex than
             * explicitly memsetting (again). */
            memset(out[i], 0, sizeof(out[i]));
        }
    }
    return rbtc_secp256k1_memcmp_var(out[0], out[1], sizeof(out[0]));
}

static int rbtc_secp256k1_ec_pubkey_sort_cmp(const void* pk1, const void* pk2, void *ctx) {
    return rbtc_secp256k1_ec_pubkey_cmp((rbtc_secp256k1_context *)ctx,
                                     *(rbtc_secp256k1_pubkey **)pk1,
                                     *(rbtc_secp256k1_pubkey **)pk2);
}

int rbtc_secp256k1_ec_pubkey_sort(const rbtc_secp256k1_context* ctx, const rbtc_secp256k1_pubkey **pubkeys, size_t n_pubkeys) {
    size_t i;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(pubkeys != NULL);
    for (i = 0; i < n_pubkeys; i++) {
        ARG_CHECK(pubkeys[i] != NULL);
    }

    /* Suppress wrong warning (fixed in MSVC 19.33) */
    #if defined(_MSC_VER) && (_MSC_VER < 1933)
    #pragma warning(push)
    #pragma warning(disable: 4090)
    #endif

    /* Casting away const is fine because neither rbtc_secp256k1_hsort nor
     * rbtc_secp256k1_ec_pubkey_sort_cmp modify the data pointed to by the cmp_data
     * argument. */
    rbtc_secp256k1_hsort(pubkeys, n_pubkeys, sizeof(*pubkeys), rbtc_secp256k1_ec_pubkey_sort_cmp, (void *)ctx);

    #if defined(_MSC_VER) && (_MSC_VER < 1933)
    #pragma warning(pop)
    #endif

    return 1;
}

static void rbtc_secp256k1_ecdsa_signature_load(const rbtc_secp256k1_context* ctx, rbtc_secp256k1_scalar* r, rbtc_secp256k1_scalar* s, const rbtc_secp256k1_ecdsa_signature* sig) {
    (void)ctx;
    if (sizeof(rbtc_secp256k1_scalar) == 32) {
        /* When the rbtc_secp256k1_scalar type is exactly 32 byte, use its
         * representation inside rbtc_secp256k1_ecdsa_signature, as conversion is very fast.
         * Note that rbtc_secp256k1_ecdsa_signature_save must use the same representation. */
        memcpy(r, &sig->data[0], 32);
        memcpy(s, &sig->data[32], 32);
    } else {
        rbtc_secp256k1_scalar_set_b32(r, &sig->data[0], NULL);
        rbtc_secp256k1_scalar_set_b32(s, &sig->data[32], NULL);
    }
}

static void rbtc_secp256k1_ecdsa_signature_save(rbtc_secp256k1_ecdsa_signature* sig, const rbtc_secp256k1_scalar* r, const rbtc_secp256k1_scalar* s) {
    if (sizeof(rbtc_secp256k1_scalar) == 32) {
        memcpy(&sig->data[0], r, 32);
        memcpy(&sig->data[32], s, 32);
    } else {
        rbtc_secp256k1_scalar_get_b32(&sig->data[0], r);
        rbtc_secp256k1_scalar_get_b32(&sig->data[32], s);
    }
}

int rbtc_secp256k1_ecdsa_signature_parse_der(const rbtc_secp256k1_context* ctx, rbtc_secp256k1_ecdsa_signature* sig, const unsigned char *input, size_t inputlen) {
    rbtc_secp256k1_scalar r, s;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(sig != NULL);
    ARG_CHECK(input != NULL);

    if (rbtc_secp256k1_ecdsa_sig_parse(&r, &s, input, inputlen)) {
        rbtc_secp256k1_ecdsa_signature_save(sig, &r, &s);
        return 1;
    } else {
        memset(sig, 0, sizeof(*sig));
        return 0;
    }
}

int rbtc_secp256k1_ecdsa_signature_parse_compact(const rbtc_secp256k1_context* ctx, rbtc_secp256k1_ecdsa_signature* sig, const unsigned char *input64) {
    rbtc_secp256k1_scalar r, s;
    int ret = 1;
    int overflow = 0;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(sig != NULL);
    ARG_CHECK(input64 != NULL);

    rbtc_secp256k1_scalar_set_b32(&r, &input64[0], &overflow);
    ret &= !overflow;
    rbtc_secp256k1_scalar_set_b32(&s, &input64[32], &overflow);
    ret &= !overflow;
    if (ret) {
        rbtc_secp256k1_ecdsa_signature_save(sig, &r, &s);
    } else {
        memset(sig, 0, sizeof(*sig));
    }
    return ret;
}

int rbtc_secp256k1_ecdsa_signature_serialize_der(const rbtc_secp256k1_context* ctx, unsigned char *output, size_t *outputlen, const rbtc_secp256k1_ecdsa_signature* sig) {
    rbtc_secp256k1_scalar r, s;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(output != NULL);
    ARG_CHECK(outputlen != NULL);
    ARG_CHECK(sig != NULL);

    rbtc_secp256k1_ecdsa_signature_load(ctx, &r, &s, sig);
    return rbtc_secp256k1_ecdsa_sig_serialize(output, outputlen, &r, &s);
}

int rbtc_secp256k1_ecdsa_signature_serialize_compact(const rbtc_secp256k1_context* ctx, unsigned char *output64, const rbtc_secp256k1_ecdsa_signature* sig) {
    rbtc_secp256k1_scalar r, s;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(output64 != NULL);
    ARG_CHECK(sig != NULL);

    rbtc_secp256k1_ecdsa_signature_load(ctx, &r, &s, sig);
    rbtc_secp256k1_scalar_get_b32(&output64[0], &r);
    rbtc_secp256k1_scalar_get_b32(&output64[32], &s);
    return 1;
}

int rbtc_secp256k1_ecdsa_signature_normalize(const rbtc_secp256k1_context* ctx, rbtc_secp256k1_ecdsa_signature *sigout, const rbtc_secp256k1_ecdsa_signature *sigin) {
    rbtc_secp256k1_scalar r, s;
    int ret = 0;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(sigin != NULL);

    rbtc_secp256k1_ecdsa_signature_load(ctx, &r, &s, sigin);
    ret = rbtc_secp256k1_scalar_is_high(&s);
    if (sigout != NULL) {
        if (ret) {
            rbtc_secp256k1_scalar_negate(&s, &s);
        }
        rbtc_secp256k1_ecdsa_signature_save(sigout, &r, &s);
    }

    return ret;
}

int rbtc_secp256k1_ecdsa_verify(const rbtc_secp256k1_context* ctx, const rbtc_secp256k1_ecdsa_signature *sig, const unsigned char *msghash32, const rbtc_secp256k1_pubkey *pubkey) {
    rbtc_secp256k1_ge q;
    rbtc_secp256k1_scalar r, s;
    rbtc_secp256k1_scalar m;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(msghash32 != NULL);
    ARG_CHECK(sig != NULL);
    ARG_CHECK(pubkey != NULL);

    rbtc_secp256k1_scalar_set_b32(&m, msghash32, NULL);
    rbtc_secp256k1_ecdsa_signature_load(ctx, &r, &s, sig);
    return (!rbtc_secp256k1_scalar_is_high(&s) &&
            rbtc_secp256k1_pubkey_load(ctx, &q, pubkey) &&
            rbtc_secp256k1_ecdsa_sig_verify(&r, &s, &q, &m));
}

static SECP256K1_INLINE void buffer_append(unsigned char *buf, unsigned int *offset, const void *data, unsigned int len) {
    memcpy(buf + *offset, data, len);
    *offset += len;
}

static int nonce_function_rfc6979_impl(const rbtc_secp256k1_hash_ctx *hash_ctx, unsigned char *nonce32, const unsigned char *msg32, const unsigned char *key32, const unsigned char *algo16, void *data, unsigned int counter) {
   unsigned char keydata[112];
   unsigned int offset = 0;
   rbtc_secp256k1_rfc6979_hmac_sha256 rng;
   unsigned int i;
   rbtc_secp256k1_scalar msg;
   unsigned char msgmod32[32];
   rbtc_secp256k1_scalar_set_b32(&msg, msg32, NULL);
   rbtc_secp256k1_scalar_get_b32(msgmod32, &msg);
   /* We feed a byte array to the PRNG as input, consisting of:
    * - the private key (32 bytes) and reduced message (32 bytes), see RFC 6979 3.2d.
    * - optionally 32 extra bytes of data, see RFC 6979 3.6 Additional Data.
    * - optionally 16 extra bytes with the algorithm name.
    * Because the arguments have distinct fixed lengths it is not possible for
    *  different argument mixtures to emulate each other and result in the same
    *  nonces.
    */
   buffer_append(keydata, &offset, key32, 32);
   buffer_append(keydata, &offset, msgmod32, 32);
   if (data != NULL) {
       buffer_append(keydata, &offset, data, 32);
   }
   if (algo16 != NULL) {
       buffer_append(keydata, &offset, algo16, 16);
   }
   rbtc_secp256k1_rfc6979_hmac_sha256_initialize(hash_ctx, &rng, keydata, offset);
   for (i = 0; i <= counter; i++) {
       rbtc_secp256k1_rfc6979_hmac_sha256_generate(hash_ctx, &rng, nonce32, 32);
   }
   rbtc_secp256k1_rfc6979_hmac_sha256_finalize(&rng);

   rbtc_secp256k1_memclear_explicit(keydata, sizeof(keydata));
   rbtc_secp256k1_rfc6979_hmac_sha256_clear(&rng);
   return 1;
}

static int nonce_function_rfc6979(unsigned char *nonce32, const unsigned char *msg32, const unsigned char *key32, const unsigned char *algo16, void *data, unsigned int counter) {
    return nonce_function_rfc6979_impl(rbtc_secp256k1_get_hash_context(rbtc_secp256k1_context_static), nonce32, msg32, key32, algo16, data, counter);
}

const rbtc_secp256k1_nonce_function rbtc_secp256k1_nonce_function_rfc6979 = nonce_function_rfc6979;
const rbtc_secp256k1_nonce_function rbtc_secp256k1_nonce_function_default = nonce_function_rfc6979;

static int rbtc_secp256k1_ecdsa_sign_inner(const rbtc_secp256k1_context* ctx, rbtc_secp256k1_scalar* r, rbtc_secp256k1_scalar* s, int* recid, const unsigned char *msg32, const unsigned char *seckey, rbtc_secp256k1_nonce_function noncefp, const void* noncedata) {
    rbtc_secp256k1_scalar sec, non, msg;
    int ret = 0;
    int is_sec_valid;
    unsigned char nonce32[32];
    unsigned int count = 0;
    /* Default initialization here is important so we won't pass uninit values to the cmov in the end */
    *r = rbtc_secp256k1_scalar_zero;
    *s = rbtc_secp256k1_scalar_zero;
    if (recid) {
        *recid = 0;
    }

    /* Fail if the secret key is invalid. */
    is_sec_valid = rbtc_secp256k1_scalar_set_b32_seckey(&sec, seckey);
    rbtc_secp256k1_scalar_cmov(&sec, &rbtc_secp256k1_scalar_one, !is_sec_valid);
    rbtc_secp256k1_scalar_set_b32(&msg, msg32, NULL);
    while (1) {
        int is_nonce_valid;

        if (noncefp == NULL) {
            /* Use ctx-aware function by default */
            ret = nonce_function_rfc6979_impl(rbtc_secp256k1_get_hash_context(ctx), nonce32, msg32, seckey, NULL, (void*)noncedata, count);
        } else {
            ret = !!noncefp(nonce32, msg32, seckey, NULL, (void*)noncedata, count);
        }

        if (!ret) {
            break;
        }
        is_nonce_valid = rbtc_secp256k1_scalar_set_b32_seckey(&non, nonce32);
        /* The nonce is still secret here, but it being invalid is less likely than 1:2^255. */
        rbtc_secp256k1_declassify(ctx, &is_nonce_valid, sizeof(is_nonce_valid));
        if (is_nonce_valid) {
            ret = rbtc_secp256k1_ecdsa_sig_sign(&ctx->ecmult_gen_ctx, r, s, &sec, &msg, &non, recid);
            /* The final signature is no longer a secret, nor is the fact that we were successful or not. */
            rbtc_secp256k1_declassify(ctx, &ret, sizeof(ret));
            if (ret) {
                break;
            }
        }
        count++;
    }
    /* We don't want to declassify is_sec_valid and therefore the range of
     * seckey. As a result is_sec_valid is included in ret only after ret was
     * used as a branching variable. */
    ret &= is_sec_valid;
    rbtc_secp256k1_memclear_explicit(nonce32, sizeof(nonce32));
    rbtc_secp256k1_scalar_clear(&msg);
    rbtc_secp256k1_scalar_clear(&non);
    rbtc_secp256k1_scalar_clear(&sec);
    rbtc_secp256k1_scalar_cmov(r, &rbtc_secp256k1_scalar_zero, !ret);
    rbtc_secp256k1_scalar_cmov(s, &rbtc_secp256k1_scalar_zero, !ret);
    if (recid) {
        const int zero = 0;
        rbtc_secp256k1_int_cmov(recid, &zero, !ret);
    }
    return ret;
}

int rbtc_secp256k1_ecdsa_sign(const rbtc_secp256k1_context* ctx, rbtc_secp256k1_ecdsa_signature *signature, const unsigned char *msghash32, const unsigned char *seckey, rbtc_secp256k1_nonce_function noncefp, const void* noncedata) {
    rbtc_secp256k1_scalar r, s;
    int ret;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(rbtc_secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ARG_CHECK(msghash32 != NULL);
    ARG_CHECK(signature != NULL);
    ARG_CHECK(seckey != NULL);

    ret = rbtc_secp256k1_ecdsa_sign_inner(ctx, &r, &s, NULL, msghash32, seckey, noncefp, noncedata);
    rbtc_secp256k1_ecdsa_signature_save(signature, &r, &s);
    return ret;
}

int rbtc_secp256k1_ec_seckey_verify(const rbtc_secp256k1_context* ctx, const unsigned char *seckey) {
    rbtc_secp256k1_scalar sec;
    int ret;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(seckey != NULL);

    ret = rbtc_secp256k1_scalar_set_b32_seckey(&sec, seckey);
    rbtc_secp256k1_scalar_clear(&sec);
    return ret;
}

static int rbtc_secp256k1_ec_pubkey_create_helper(const rbtc_secp256k1_ecmult_gen_context *ecmult_gen_ctx, rbtc_secp256k1_scalar *seckey_scalar, rbtc_secp256k1_ge *p, const unsigned char *seckey) {
    rbtc_secp256k1_gej pj;
    int ret;

    ret = rbtc_secp256k1_scalar_set_b32_seckey(seckey_scalar, seckey);
    rbtc_secp256k1_scalar_cmov(seckey_scalar, &rbtc_secp256k1_scalar_one, !ret);

    rbtc_secp256k1_ecmult_gen(ecmult_gen_ctx, &pj, seckey_scalar);
    rbtc_secp256k1_ge_set_gej(p, &pj);
    rbtc_secp256k1_gej_clear(&pj);
    return ret;
}

int rbtc_secp256k1_ec_pubkey_create(const rbtc_secp256k1_context* ctx, rbtc_secp256k1_pubkey *pubkey, const unsigned char *seckey) {
    rbtc_secp256k1_ge p;
    rbtc_secp256k1_scalar seckey_scalar;
    int ret = 0;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(pubkey != NULL);
    memset(pubkey, 0, sizeof(*pubkey));
    ARG_CHECK(rbtc_secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ARG_CHECK(seckey != NULL);

    ret = rbtc_secp256k1_ec_pubkey_create_helper(&ctx->ecmult_gen_ctx, &seckey_scalar, &p, seckey);
    rbtc_secp256k1_pubkey_save(pubkey, &p);
    rbtc_secp256k1_memczero(pubkey, sizeof(*pubkey), !ret);

    rbtc_secp256k1_scalar_clear(&seckey_scalar);
    return ret;
}

int rbtc_secp256k1_ec_seckey_negate(const rbtc_secp256k1_context* ctx, unsigned char *seckey) {
    rbtc_secp256k1_scalar sec;
    int ret = 0;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(seckey != NULL);

    ret = rbtc_secp256k1_scalar_set_b32_seckey(&sec, seckey);
    rbtc_secp256k1_scalar_cmov(&sec, &rbtc_secp256k1_scalar_zero, !ret);
    rbtc_secp256k1_scalar_negate(&sec, &sec);
    rbtc_secp256k1_scalar_get_b32(seckey, &sec);

    rbtc_secp256k1_scalar_clear(&sec);
    return ret;
}

int rbtc_secp256k1_ec_pubkey_negate(const rbtc_secp256k1_context* ctx, rbtc_secp256k1_pubkey *pubkey) {
    int ret = 0;
    rbtc_secp256k1_ge p;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(pubkey != NULL);

    ret = rbtc_secp256k1_pubkey_load(ctx, &p, pubkey);
    memset(pubkey, 0, sizeof(*pubkey));
    if (ret) {
        rbtc_secp256k1_ge_neg(&p, &p);
        rbtc_secp256k1_pubkey_save(pubkey, &p);
    }
    return ret;
}


static int rbtc_secp256k1_ec_seckey_tweak_add_helper(rbtc_secp256k1_scalar *sec, const unsigned char *tweak32) {
    rbtc_secp256k1_scalar term;
    int overflow = 0;
    int ret = 0;

    rbtc_secp256k1_scalar_set_b32(&term, tweak32, &overflow);
    ret = (!overflow) & rbtc_secp256k1_eckey_privkey_tweak_add(sec, &term);
    rbtc_secp256k1_scalar_clear(&term);
    return ret;
}

int rbtc_secp256k1_ec_seckey_tweak_add(const rbtc_secp256k1_context* ctx, unsigned char *seckey, const unsigned char *tweak32) {
    rbtc_secp256k1_scalar sec;
    int ret = 0;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(seckey != NULL);
    ARG_CHECK(tweak32 != NULL);

    ret = rbtc_secp256k1_scalar_set_b32_seckey(&sec, seckey);
    ret &= rbtc_secp256k1_ec_seckey_tweak_add_helper(&sec, tweak32);
    rbtc_secp256k1_scalar_cmov(&sec, &rbtc_secp256k1_scalar_zero, !ret);
    rbtc_secp256k1_scalar_get_b32(seckey, &sec);

    rbtc_secp256k1_scalar_clear(&sec);
    return ret;
}

static int rbtc_secp256k1_ec_pubkey_tweak_add_helper(rbtc_secp256k1_ge *p, const unsigned char *tweak32) {
    rbtc_secp256k1_scalar term;
    int overflow = 0;
    rbtc_secp256k1_scalar_set_b32(&term, tweak32, &overflow);
    return !overflow && rbtc_secp256k1_eckey_pubkey_tweak_add(p, &term);
}

int rbtc_secp256k1_ec_pubkey_tweak_add(const rbtc_secp256k1_context* ctx, rbtc_secp256k1_pubkey *pubkey, const unsigned char *tweak32) {
    rbtc_secp256k1_ge p;
    int ret = 0;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(pubkey != NULL);
    ARG_CHECK(tweak32 != NULL);

    ret = rbtc_secp256k1_pubkey_load(ctx, &p, pubkey);
    memset(pubkey, 0, sizeof(*pubkey));
    ret = ret && rbtc_secp256k1_ec_pubkey_tweak_add_helper(&p, tweak32);
    if (ret) {
        rbtc_secp256k1_pubkey_save(pubkey, &p);
    }

    return ret;
}

int rbtc_secp256k1_ec_seckey_tweak_mul(const rbtc_secp256k1_context* ctx, unsigned char *seckey, const unsigned char *tweak32) {
    rbtc_secp256k1_scalar factor;
    rbtc_secp256k1_scalar sec;
    int ret = 0;
    int overflow = 0;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(seckey != NULL);
    ARG_CHECK(tweak32 != NULL);

    rbtc_secp256k1_scalar_set_b32(&factor, tweak32, &overflow);
    ret = rbtc_secp256k1_scalar_set_b32_seckey(&sec, seckey);
    ret &= (!overflow) & rbtc_secp256k1_eckey_privkey_tweak_mul(&sec, &factor);
    rbtc_secp256k1_scalar_cmov(&sec, &rbtc_secp256k1_scalar_zero, !ret);
    rbtc_secp256k1_scalar_get_b32(seckey, &sec);

    rbtc_secp256k1_scalar_clear(&sec);
    rbtc_secp256k1_scalar_clear(&factor);
    return ret;
}

int rbtc_secp256k1_ec_pubkey_tweak_mul(const rbtc_secp256k1_context* ctx, rbtc_secp256k1_pubkey *pubkey, const unsigned char *tweak32) {
    rbtc_secp256k1_ge p;
    rbtc_secp256k1_scalar factor;
    int ret = 0;
    int overflow = 0;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(pubkey != NULL);
    ARG_CHECK(tweak32 != NULL);

    rbtc_secp256k1_scalar_set_b32(&factor, tweak32, &overflow);
    ret = !overflow && rbtc_secp256k1_pubkey_load(ctx, &p, pubkey);
    memset(pubkey, 0, sizeof(*pubkey));
    if (ret) {
        if (rbtc_secp256k1_eckey_pubkey_tweak_mul(&p, &factor)) {
            rbtc_secp256k1_pubkey_save(pubkey, &p);
        } else {
            ret = 0;
        }
    }

    return ret;
}

int rbtc_secp256k1_context_randomize(rbtc_secp256k1_context* ctx, const unsigned char *seed32) {
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(rbtc_secp256k1_context_is_proper(ctx));

    if (rbtc_secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx)) {
        rbtc_secp256k1_ecmult_gen_blind(&ctx->ecmult_gen_ctx, rbtc_secp256k1_get_hash_context(ctx), seed32);
    }
    return 1;
}

int rbtc_secp256k1_ec_pubkey_combine(const rbtc_secp256k1_context* ctx, rbtc_secp256k1_pubkey *pubnonce, const rbtc_secp256k1_pubkey * const *pubnonces, size_t n) {
    size_t i;
    rbtc_secp256k1_gej Qj;
    rbtc_secp256k1_ge Q;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(pubnonce != NULL);
    memset(pubnonce, 0, sizeof(*pubnonce));
    ARG_CHECK(n >= 1);
    ARG_CHECK(pubnonces != NULL);

    rbtc_secp256k1_gej_set_infinity(&Qj);

    for (i = 0; i < n; i++) {
        ARG_CHECK(pubnonces[i] != NULL);
        rbtc_secp256k1_pubkey_load(ctx, &Q, pubnonces[i]);
        rbtc_secp256k1_gej_add_ge(&Qj, &Qj, &Q);
    }
    if (rbtc_secp256k1_gej_is_infinity(&Qj)) {
        return 0;
    }
    rbtc_secp256k1_ge_set_gej(&Q, &Qj);
    rbtc_secp256k1_pubkey_save(pubnonce, &Q);
    return 1;
}

int rbtc_secp256k1_tagged_sha256(const rbtc_secp256k1_context* ctx, unsigned char *hash32, const unsigned char *tag, size_t taglen, const unsigned char *msg, size_t msglen) {
    rbtc_secp256k1_sha256 sha;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(hash32 != NULL);
    ARG_CHECK(tag != NULL);
    ARG_CHECK(msg != NULL);

    rbtc_secp256k1_sha256_initialize_tagged(rbtc_secp256k1_get_hash_context(ctx), &sha, tag, taglen);
    rbtc_secp256k1_sha256_write(rbtc_secp256k1_get_hash_context(ctx), &sha, msg, msglen);
    rbtc_secp256k1_sha256_finalize(rbtc_secp256k1_get_hash_context(ctx), &sha, hash32);
    rbtc_secp256k1_sha256_clear(&sha);
    return 1;
}

#ifdef ENABLE_MODULE_ECDH
# include "modules/ecdh/main_impl.h"
#endif

#ifdef ENABLE_MODULE_RECOVERY
# include "modules/recovery/main_impl.h"
#endif

#ifdef ENABLE_MODULE_EXTRAKEYS
# include "modules/extrakeys/main_impl.h"
#endif

#ifdef ENABLE_MODULE_SCHNORRSIG
# include "modules/schnorrsig/main_impl.h"
#endif

#ifdef ENABLE_MODULE_MUSIG
# include "modules/musig/main_impl.h"
#endif

#ifdef ENABLE_MODULE_ELLSWIFT
# include "modules/ellswift/main_impl.h"
#endif

#ifdef ENABLE_MODULE_BATCH
# include "modules/batch/main_impl.h"
# ifdef ENABLE_MODULE_EXTRAKEYS
#  include "modules/extrakeys/batch_add_impl.h"
# endif
# ifdef ENABLE_MODULE_SCHNORRSIG
#  include "modules/schnorrsig/batch_add_impl.h"
# endif
#endif
