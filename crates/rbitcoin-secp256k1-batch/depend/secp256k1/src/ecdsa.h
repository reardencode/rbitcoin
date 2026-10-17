/***********************************************************************
 * Copyright (c) 2013, 2014 Pieter Wuille                              *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_ECDSA_H
#define SECP256K1_ECDSA_H

#include <stddef.h>

#include "scalar.h"
#include "group.h"
#include "ecmult.h"

static int rbtc_secp256k1_ecdsa_sig_parse(rbtc_secp256k1_scalar *r, rbtc_secp256k1_scalar *s, const unsigned char *sig, size_t size);
static int rbtc_secp256k1_ecdsa_sig_serialize(unsigned char *sig, size_t *size, const rbtc_secp256k1_scalar *r, const rbtc_secp256k1_scalar *s);
static int rbtc_secp256k1_ecdsa_sig_verify(const rbtc_secp256k1_scalar* r, const rbtc_secp256k1_scalar* s, const rbtc_secp256k1_ge *pubkey, const rbtc_secp256k1_scalar *message);
static int rbtc_secp256k1_ecdsa_sig_sign(const rbtc_secp256k1_ecmult_gen_context *ctx, rbtc_secp256k1_scalar* r, rbtc_secp256k1_scalar* s, const rbtc_secp256k1_scalar *seckey, const rbtc_secp256k1_scalar *message, const rbtc_secp256k1_scalar *nonce, int *recid);

#endif /* SECP256K1_ECDSA_H */
