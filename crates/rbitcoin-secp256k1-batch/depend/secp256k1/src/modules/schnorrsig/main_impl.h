/***********************************************************************
 * Copyright (c) 2018-2020 Andrew Poelstra, Jonas Nick                 *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_MODULE_SCHNORRSIG_MAIN_H
#define SECP256K1_MODULE_SCHNORRSIG_MAIN_H

#include "../../../include/secp256k1.h"
#include "../../../include/secp256k1_schnorrsig.h"
#include "../../hash.h"

/* Initializes SHA256 with fixed midstate. This midstate was computed by applying
 * SHA256 to SHA256("BIP0340/nonce")||SHA256("BIP0340/nonce"). */
static void rbtc_secp256k1_nonce_function_bip340_sha256_tagged(rbtc_secp256k1_sha256 *sha) {
    static const uint32_t midstate[8] = {
        0x46615b35ul, 0xf4bfbff7ul, 0x9f8dc671ul, 0x83627ab3ul,
        0x60217180ul, 0x57358661ul, 0x21a29e54ul, 0x68b07b4cul
    };
    rbtc_secp256k1_sha256_initialize_midstate(sha, 64, midstate);
}

/* Initializes SHA256 with fixed midstate. This midstate was computed by applying
 * SHA256 to SHA256("BIP0340/aux")||SHA256("BIP0340/aux"). */
static void rbtc_secp256k1_nonce_function_bip340_sha256_tagged_aux(rbtc_secp256k1_sha256 *sha) {
    static const uint32_t midstate[8] = {
        0x24dd3219ul, 0x4eba7e70ul, 0xca0fabb9ul, 0x0fa3166dul,
        0x3afbe4b1ul, 0x4c44df97ul, 0x4aac2739ul, 0x249e850aul
    };
    rbtc_secp256k1_sha256_initialize_midstate(sha, 64, midstate);
}

/* algo argument for nonce_function_bip340 to derive the nonce exactly as stated in BIP-340
 * by using the correct tagged hash function. */
static const unsigned char bip340_algo[] = {'B', 'I', 'P', '0', '3', '4', '0', '/', 'n', 'o', 'n', 'c', 'e'};

static const unsigned char schnorrsig_extraparams_magic[4] = SECP256K1_SCHNORRSIG_EXTRAPARAMS_MAGIC;

static int nonce_function_bip340_impl(const rbtc_secp256k1_hash_ctx *hash_ctx, unsigned char *nonce32, const unsigned char *msg, size_t msglen, const unsigned char *key32, const unsigned char *xonly_pk32, const unsigned char *algo, size_t algolen, void *data) {
    rbtc_secp256k1_sha256 sha;
    unsigned char masked_key[32];
    int i;

    if (algo == NULL) {
        return 0;
    }

    if (data != NULL) {
        rbtc_secp256k1_nonce_function_bip340_sha256_tagged_aux(&sha);
        rbtc_secp256k1_sha256_write(hash_ctx, &sha, data, 32);
        rbtc_secp256k1_sha256_finalize(hash_ctx, &sha, masked_key);
        for (i = 0; i < 32; i++) {
            masked_key[i] ^= key32[i];
        }
    } else {
        /* Precomputed TaggedHash("BIP0340/aux", 0x0000...00); */
        static const unsigned char ZERO_MASK[32] = {
              84, 241, 105, 207, 201, 226, 229, 114,
             116, 128,  68,  31, 144, 186,  37, 196,
             136, 244,  97, 199,  11,  94, 165, 220,
             170, 247, 175, 105, 39,  10, 165,  20
        };
        for (i = 0; i < 32; i++) {
            masked_key[i] = key32[i] ^ ZERO_MASK[i];
        }
    }

    /* Tag the hash with algo which is important to avoid nonce reuse across
     * algorithms. If this nonce function is used in BIP-340 signing as defined
     * in the spec, an optimized tagging implementation is used. */
    if (algolen == sizeof(bip340_algo)
            && rbtc_secp256k1_memcmp_var(algo, bip340_algo, algolen) == 0) {
        rbtc_secp256k1_nonce_function_bip340_sha256_tagged(&sha);
    } else {
        rbtc_secp256k1_sha256_initialize_tagged(hash_ctx, &sha, algo, algolen);
    }

    /* Hash masked-key||pk||msg using the tagged hash as per the spec */
    rbtc_secp256k1_sha256_write(hash_ctx, &sha, masked_key, 32);
    rbtc_secp256k1_sha256_write(hash_ctx, &sha, xonly_pk32, 32);
    rbtc_secp256k1_sha256_write(hash_ctx, &sha, msg, msglen);
    rbtc_secp256k1_sha256_finalize(hash_ctx, &sha, nonce32);
    rbtc_secp256k1_sha256_clear(&sha);
    rbtc_secp256k1_memclear_explicit(masked_key, sizeof(masked_key));

    return 1;
}

static int nonce_function_bip340(unsigned char *nonce32, const unsigned char *msg, size_t msglen, const unsigned char *key32, const unsigned char *xonly_pk32, const unsigned char *algo, size_t algolen, void *data) {
    return nonce_function_bip340_impl(rbtc_secp256k1_get_hash_context(rbtc_secp256k1_context_static), nonce32, msg, msglen, key32, xonly_pk32, algo, algolen, data);
}

const rbtc_secp256k1_nonce_function_hardened rbtc_secp256k1_nonce_function_bip340 = nonce_function_bip340;

/* Initializes SHA256 with fixed midstate. This midstate was computed by applying
 * SHA256 to SHA256("BIP0340/challenge")||SHA256("BIP0340/challenge"). */
static void rbtc_secp256k1_schnorrsig_sha256_tagged(rbtc_secp256k1_sha256 *sha) {
    static const uint32_t midstate[8] = {
        0x9cecba11ul, 0x23925381ul, 0x11679112ul, 0xd1627e0ful,
        0x97c87550ul, 0x003cc765ul, 0x90f61164ul, 0x33e9b66aul
    };
    rbtc_secp256k1_sha256_initialize_midstate(sha, 64, midstate);
}

static void rbtc_secp256k1_schnorrsig_challenge(const rbtc_secp256k1_hash_ctx *hash_ctx, rbtc_secp256k1_scalar* e, const unsigned char *r32, const unsigned char *msg, size_t msglen, const unsigned char *pubkey32)
{
    unsigned char buf[32];
    rbtc_secp256k1_sha256 sha;

    /* tagged hash(r.x, pk.x, msg) */
    rbtc_secp256k1_schnorrsig_sha256_tagged(&sha);
    rbtc_secp256k1_sha256_write(hash_ctx, &sha, r32, 32);
    rbtc_secp256k1_sha256_write(hash_ctx, &sha, pubkey32, 32);
    rbtc_secp256k1_sha256_write(hash_ctx, &sha, msg, msglen);
    rbtc_secp256k1_sha256_finalize(hash_ctx, &sha, buf);
    /* Set scalar e to the challenge hash modulo the curve order as per
     * BIP340. */
    rbtc_secp256k1_scalar_set_b32(e, buf, NULL);
}

static int rbtc_secp256k1_schnorrsig_sign_internal(const rbtc_secp256k1_context* ctx, unsigned char *sig64, const unsigned char *msg, size_t msglen, const rbtc_secp256k1_keypair *keypair, rbtc_secp256k1_nonce_function_hardened noncefp, void *ndata) {
    rbtc_secp256k1_scalar sk;
    rbtc_secp256k1_scalar e;
    rbtc_secp256k1_scalar k;
    rbtc_secp256k1_gej rj;
    rbtc_secp256k1_ge pk;
    rbtc_secp256k1_ge r;
    unsigned char nonce32[32] = { 0 };
    unsigned char pk_buf[32];
    unsigned char seckey[32];
    int ret = 1;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(rbtc_secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ARG_CHECK(sig64 != NULL);
    ARG_CHECK(msg != NULL || msglen == 0);
    ARG_CHECK(keypair != NULL);

    ret &= rbtc_secp256k1_keypair_load(ctx, &sk, &pk, keypair);
    /* Because we are signing for a x-only pubkey, the secret key is negated
     * before signing if the point corresponding to the secret key does not
     * have an even Y. */
    if (rbtc_secp256k1_fe_is_odd(&pk.y)) {
        rbtc_secp256k1_scalar_negate(&sk, &sk);
    }

    rbtc_secp256k1_scalar_get_b32(seckey, &sk);
    rbtc_secp256k1_fe_get_b32(pk_buf, &pk.x);

    /* Compute nonce */
    if (noncefp == NULL || noncefp == rbtc_secp256k1_nonce_function_bip340) {
        /* Use context-aware nonce function by default */
        ret &= nonce_function_bip340_impl(rbtc_secp256k1_get_hash_context(ctx), nonce32, msg, msglen, seckey, pk_buf, bip340_algo, sizeof(bip340_algo), ndata);
    } else {
        ret &= !!noncefp(nonce32, msg, msglen, seckey, pk_buf, bip340_algo, sizeof(bip340_algo), ndata);
    }

    rbtc_secp256k1_scalar_set_b32(&k, nonce32, NULL);
    ret &= !rbtc_secp256k1_scalar_is_zero(&k);
    rbtc_secp256k1_scalar_cmov(&k, &rbtc_secp256k1_scalar_one, !ret);

    rbtc_secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &rj, &k);
    rbtc_secp256k1_ge_set_gej(&r, &rj);

    /* We declassify r to allow using it as a branch point. This is fine
     * because r is not a secret. */
    rbtc_secp256k1_declassify(ctx, &r, sizeof(r));
    rbtc_secp256k1_fe_normalize_var(&r.y);
    if (rbtc_secp256k1_fe_is_odd(&r.y)) {
        rbtc_secp256k1_scalar_negate(&k, &k);
    }
    rbtc_secp256k1_fe_normalize_var(&r.x);
    rbtc_secp256k1_fe_get_b32(&sig64[0], &r.x);

    rbtc_secp256k1_schnorrsig_challenge(rbtc_secp256k1_get_hash_context(ctx), &e, &sig64[0], msg, msglen, pk_buf);
    rbtc_secp256k1_scalar_mul(&e, &e, &sk);
    rbtc_secp256k1_scalar_add(&e, &e, &k);
    rbtc_secp256k1_scalar_get_b32(&sig64[32], &e);

    rbtc_secp256k1_memczero(sig64, 64, !ret);
    rbtc_secp256k1_scalar_clear(&k);
    rbtc_secp256k1_scalar_clear(&sk);
    rbtc_secp256k1_memclear_explicit(seckey, sizeof(seckey));
    rbtc_secp256k1_memclear_explicit(nonce32, sizeof(nonce32));
    rbtc_secp256k1_gej_clear(&rj);

    return ret;
}

int rbtc_secp256k1_schnorrsig_sign32(const rbtc_secp256k1_context* ctx, unsigned char *sig64, const unsigned char *msg32, const rbtc_secp256k1_keypair *keypair, const unsigned char *aux_rand32) {
    /* We cast away const from the passed aux_rand32 argument since we know the default nonce function does not modify it. */
    return rbtc_secp256k1_schnorrsig_sign_internal(ctx, sig64, msg32, 32, keypair, rbtc_secp256k1_nonce_function_bip340, (unsigned char*)aux_rand32);
}

int rbtc_secp256k1_schnorrsig_sign(const rbtc_secp256k1_context* ctx, unsigned char *sig64, const unsigned char *msg32, const rbtc_secp256k1_keypair *keypair, const unsigned char *aux_rand32) {
    return rbtc_secp256k1_schnorrsig_sign32(ctx, sig64, msg32, keypair, aux_rand32);
}

int rbtc_secp256k1_schnorrsig_sign_custom(const rbtc_secp256k1_context* ctx, unsigned char *sig64, const unsigned char *msg, size_t msglen, const rbtc_secp256k1_keypair *keypair, rbtc_secp256k1_schnorrsig_extraparams *extraparams) {
    rbtc_secp256k1_nonce_function_hardened noncefp = NULL;
    void *ndata = NULL;
    VERIFY_CHECK(ctx != NULL);

    if (extraparams != NULL) {
        ARG_CHECK(rbtc_secp256k1_memcmp_var(extraparams->magic,
                                       schnorrsig_extraparams_magic,
                                       sizeof(extraparams->magic)) == 0);
        noncefp = extraparams->noncefp;
        ndata = extraparams->ndata;
    }
    return rbtc_secp256k1_schnorrsig_sign_internal(ctx, sig64, msg, msglen, keypair, noncefp, ndata);
}

int rbtc_secp256k1_schnorrsig_verify(const rbtc_secp256k1_context* ctx, const unsigned char *sig64, const unsigned char *msg, size_t msglen, const rbtc_secp256k1_xonly_pubkey *pubkey) {
    rbtc_secp256k1_scalar s;
    rbtc_secp256k1_scalar e;
    rbtc_secp256k1_gej rj;
    rbtc_secp256k1_ge pk;
    rbtc_secp256k1_gej pkj;
    rbtc_secp256k1_fe rx;
    rbtc_secp256k1_ge r;
    unsigned char buf[32];
    int overflow;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(sig64 != NULL);
    ARG_CHECK(msg != NULL || msglen == 0);
    ARG_CHECK(pubkey != NULL);

    if (!rbtc_secp256k1_fe_set_b32_limit(&rx, &sig64[0])) {
        return 0;
    }

    rbtc_secp256k1_scalar_set_b32(&s, &sig64[32], &overflow);
    if (overflow) {
        return 0;
    }

    if (!rbtc_secp256k1_xonly_pubkey_load(ctx, &pk, pubkey)) {
        return 0;
    }

    /* Compute e. */
    rbtc_secp256k1_fe_get_b32(buf, &pk.x);
    rbtc_secp256k1_schnorrsig_challenge(rbtc_secp256k1_get_hash_context(ctx), &e, &sig64[0], msg, msglen, buf);

    /* Compute rj =  s*G + (-e)*pkj */
    rbtc_secp256k1_scalar_negate(&e, &e);
    rbtc_secp256k1_gej_set_ge(&pkj, &pk);
    rbtc_secp256k1_ecmult(&rj, &pkj, &e, &s);

    rbtc_secp256k1_ge_set_gej_var(&r, &rj);
    if (rbtc_secp256k1_ge_is_infinity(&r)) {
        return 0;
    }

    rbtc_secp256k1_fe_normalize_var(&r.y);
    return !rbtc_secp256k1_fe_is_odd(&r.y) &&
           rbtc_secp256k1_fe_equal(&rx, &r.x);
}

#endif
