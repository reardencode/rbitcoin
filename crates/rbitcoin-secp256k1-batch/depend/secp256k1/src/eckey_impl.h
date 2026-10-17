/***********************************************************************
 * Copyright (c) 2013, 2014 Pieter Wuille                              *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_ECKEY_IMPL_H
#define SECP256K1_ECKEY_IMPL_H

#include "eckey.h"

#include "util.h"
#include "scalar.h"
#include "field.h"
#include "group.h"
#include "ecmult_gen.h"

static int rbtc_secp256k1_eckey_pubkey_parse(rbtc_secp256k1_ge *elem, const unsigned char *pub, size_t size) {
    if (size == 33 && (pub[0] == SECP256K1_TAG_PUBKEY_EVEN || pub[0] == SECP256K1_TAG_PUBKEY_ODD)) {
        rbtc_secp256k1_fe x;
        return rbtc_secp256k1_fe_set_b32_limit(&x, pub+1) && rbtc_secp256k1_ge_set_xo_var(elem, &x, pub[0] == SECP256K1_TAG_PUBKEY_ODD);
    } else if (size == 65 && (pub[0] == SECP256K1_TAG_PUBKEY_UNCOMPRESSED || pub[0] == SECP256K1_TAG_PUBKEY_HYBRID_EVEN || pub[0] == SECP256K1_TAG_PUBKEY_HYBRID_ODD)) {
        rbtc_secp256k1_fe x, y;
        if (!rbtc_secp256k1_fe_set_b32_limit(&x, pub+1) || !rbtc_secp256k1_fe_set_b32_limit(&y, pub+33)) {
            return 0;
        }
        rbtc_secp256k1_ge_set_xy(elem, &x, &y);
        if ((pub[0] == SECP256K1_TAG_PUBKEY_HYBRID_EVEN || pub[0] == SECP256K1_TAG_PUBKEY_HYBRID_ODD) &&
            rbtc_secp256k1_fe_is_odd(&y) != (pub[0] == SECP256K1_TAG_PUBKEY_HYBRID_ODD)) {
            return 0;
        }
        return rbtc_secp256k1_ge_is_valid_var(elem);
    } else {
        return 0;
    }
}

static void rbtc_secp256k1_eckey_pubkey_serialize33(rbtc_secp256k1_ge *elem, unsigned char *pub33) {
    VERIFY_CHECK(!rbtc_secp256k1_ge_is_infinity(elem));

    rbtc_secp256k1_fe_normalize_var(&elem->x);
    rbtc_secp256k1_fe_normalize_var(&elem->y);
    pub33[0] = rbtc_secp256k1_fe_is_odd(&elem->y) ? SECP256K1_TAG_PUBKEY_ODD : SECP256K1_TAG_PUBKEY_EVEN;
    rbtc_secp256k1_fe_get_b32(&pub33[1], &elem->x);
}

static void rbtc_secp256k1_eckey_pubkey_serialize65(rbtc_secp256k1_ge *elem, unsigned char *pub65) {
    VERIFY_CHECK(!rbtc_secp256k1_ge_is_infinity(elem));

    rbtc_secp256k1_fe_normalize_var(&elem->x);
    rbtc_secp256k1_fe_normalize_var(&elem->y);
    pub65[0] = SECP256K1_TAG_PUBKEY_UNCOMPRESSED;
    rbtc_secp256k1_fe_get_b32(&pub65[1], &elem->x);
    rbtc_secp256k1_fe_get_b32(&pub65[33], &elem->y);
}

static int rbtc_secp256k1_eckey_privkey_tweak_add(rbtc_secp256k1_scalar *key, const rbtc_secp256k1_scalar *tweak) {
    rbtc_secp256k1_scalar_add(key, key, tweak);
    return !rbtc_secp256k1_scalar_is_zero(key);
}

static int rbtc_secp256k1_eckey_pubkey_tweak_add(rbtc_secp256k1_ge *key, const rbtc_secp256k1_scalar *tweak) {
    rbtc_secp256k1_gej pt;
    rbtc_secp256k1_gej_set_ge(&pt, key);
    rbtc_secp256k1_ecmult(&pt, &pt, &rbtc_secp256k1_scalar_one, tweak);

    if (rbtc_secp256k1_gej_is_infinity(&pt)) {
        return 0;
    }
    rbtc_secp256k1_ge_set_gej(key, &pt);
    return 1;
}

static int rbtc_secp256k1_eckey_privkey_tweak_mul(rbtc_secp256k1_scalar *key, const rbtc_secp256k1_scalar *tweak) {
    int ret;
    ret = !rbtc_secp256k1_scalar_is_zero(tweak);

    rbtc_secp256k1_scalar_mul(key, key, tweak);
    return ret;
}

static int rbtc_secp256k1_eckey_pubkey_tweak_mul(rbtc_secp256k1_ge *key, const rbtc_secp256k1_scalar *tweak) {
    rbtc_secp256k1_gej pt;
    if (rbtc_secp256k1_scalar_is_zero(tweak)) {
        return 0;
    }

    rbtc_secp256k1_gej_set_ge(&pt, key);
    rbtc_secp256k1_ecmult(&pt, &pt, tweak, NULL);
    rbtc_secp256k1_ge_set_gej(key, &pt);
    return 1;
}

#endif /* SECP256K1_ECKEY_IMPL_H */
