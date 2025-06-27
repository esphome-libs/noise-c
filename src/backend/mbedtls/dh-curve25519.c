#include "noise/defines.h"
#if NOISE_USE_MBEDTLS && NOISE_USE_CURVE25519

#include "protocol/internal.h"
#include <mbedtls/version.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/ecp.h>
#include <mbedtls/bignum.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/error.h>
#include <string.h>

typedef struct
{
    struct NoiseDHState_s parent;
    uint8_t private_key[32];
    uint8_t public_key[32];
} NoiseCurve25519State;

static int noise_curve25519_generate_keypair
    (NoiseDHState *state, const NoiseDHState *other)
{
    NoiseCurve25519State *st = (NoiseCurve25519State *)state;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ecdh_context ecdh;
    int ret;
    
    /* Initialize contexts */
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_ecdh_init(&ecdh);
    
    /* Seed the RNG */
    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);
    if (ret != 0)
        goto cleanup;
    
    /* Setup Curve25519 */
    ret = mbedtls_ecdh_setup(&ecdh, MBEDTLS_ECP_DP_CURVE25519);
    if (ret != 0)
        goto cleanup;
    
    /* Generate keypair using ECP directly since we need access to private key */
    mbedtls_ecp_group grp;
    mbedtls_mpi d;
    mbedtls_ecp_point Q;
    
    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);
    mbedtls_ecp_point_init(&Q);
    
    /* Load Curve25519 group */
    ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_CURVE25519);
    if (ret != 0) {
        mbedtls_ecp_group_free(&grp);
        mbedtls_mpi_free(&d);
        mbedtls_ecp_point_free(&Q);
        goto cleanup;
    }
    
    /* Generate keypair */
    ret = mbedtls_ecp_gen_keypair(&grp, &d, &Q,
                                  mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0) {
        mbedtls_ecp_group_free(&grp);
        mbedtls_mpi_free(&d);
        mbedtls_ecp_point_free(&Q);
        goto cleanup;
    }
    
    /* Export private key */
    ret = mbedtls_mpi_write_binary(&d, st->private_key, 32);
    if (ret != 0) {
        mbedtls_ecp_group_free(&grp);
        mbedtls_mpi_free(&d);
        mbedtls_ecp_point_free(&Q);
        goto cleanup;
    }
    
    /* Export public key - for Curve25519 we need the X coordinate */
    size_t olen;
    uint8_t buf[66];
    ret = mbedtls_ecp_point_write_binary(&grp, &Q, MBEDTLS_ECP_PF_UNCOMPRESSED,
                                         &olen, buf, sizeof(buf));
    if (ret == 0) {
        /* For Curve25519, extract just the X coordinate */
        if (olen == 33 && buf[0] == 0x04) {
            /* Uncompressed format with 0x04 prefix */
            memcpy(st->public_key, buf + 1, 32);
        } else if (olen == 32) {
            /* Raw X coordinate */
            memcpy(st->public_key, buf, 32);
        } else {
            ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
        }
    }
    
    mbedtls_ecp_group_free(&grp);
    mbedtls_mpi_free(&d);
    mbedtls_ecp_point_free(&Q);
    
    if (ret == 0)
        state->key_type = NOISE_KEY_TYPE_KEYPAIR;
    
cleanup:
    mbedtls_ecdh_free(&ecdh);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    
    return ret == 0 ? NOISE_ERROR_NONE : NOISE_ERROR_SYSTEM;
}

static int noise_curve25519_set_keypair
    (NoiseDHState *state, const uint8_t *private_key, const uint8_t *public_key)
{
    NoiseCurve25519State *st = (NoiseCurve25519State *)state;
    memcpy(st->private_key, private_key, 32);
    memcpy(st->public_key, public_key, 32);
    state->key_type = NOISE_KEY_TYPE_KEYPAIR;
    return NOISE_ERROR_NONE;
}

static int noise_curve25519_set_keypair_private
    (NoiseDHState *state, const uint8_t *private_key)
{
    NoiseCurve25519State *st = (NoiseCurve25519State *)state;
    mbedtls_ecp_group grp;
    mbedtls_mpi d;
    mbedtls_ecp_point Q;
    int ret;
    
    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);
    mbedtls_ecp_point_init(&Q);
    
    /* Load Curve25519 group */
    ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_CURVE25519);
    if (ret != 0)
        goto cleanup;
    
    /* Import private key */
    ret = mbedtls_mpi_read_binary(&d, private_key, 32);
    if (ret != 0)
        goto cleanup;
    
    /* Calculate public key: Q = d * G */
    ret = mbedtls_ecp_mul(&grp, &Q, &d, &grp.G, NULL, NULL);
    if (ret != 0)
        goto cleanup;
    
    /* Store private key */
    memcpy(st->private_key, private_key, 32);
    
    /* Export public key - for Curve25519 we need the X coordinate */
    /* Use the raw scalar multiplication result */
    size_t olen;
    uint8_t buf[66];
    ret = mbedtls_ecp_point_write_binary(&grp, &Q, MBEDTLS_ECP_PF_UNCOMPRESSED,
                                         &olen, buf, sizeof(buf));
    if (ret == 0) {
        /* For Curve25519, extract just the X coordinate */
        if (olen == 33 && buf[0] == 0x04) {
            /* Uncompressed format with 0x04 prefix */
            memcpy(st->public_key, buf + 1, 32);
        } else if (olen == 32) {
            /* Raw X coordinate */
            memcpy(st->public_key, buf, 32);
        } else {
            ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
        }
    }
    
    if (ret == 0)
        state->key_type = NOISE_KEY_TYPE_KEYPAIR;
    
cleanup:
    mbedtls_ecp_point_free(&Q);
    mbedtls_mpi_free(&d);
    mbedtls_ecp_group_free(&grp);
    
    return ret == 0 ? NOISE_ERROR_NONE : NOISE_ERROR_INVALID_PRIVATE_KEY;
}

static int noise_curve25519_validate_public_key
    (const NoiseDHState *state, const uint8_t *public_key)
{
    /* Basic validation - reject all-zero public key */
    static const uint8_t zero[32] = {0};
    if (!noise_is_zero(public_key, 32))
        return NOISE_ERROR_NONE;
    else
        return NOISE_ERROR_INVALID_PUBLIC_KEY;
}

static int noise_curve25519_copy
    (NoiseDHState *state, const NoiseDHState *from, const NoiseDHState *other)
{
    NoiseCurve25519State *st = (NoiseCurve25519State *)state;
    const NoiseCurve25519State *from_st = (const NoiseCurve25519State *)from;
    state->key_type = from->key_type;
    if (from->key_type == NOISE_KEY_TYPE_KEYPAIR) {
        memcpy(st->private_key, from_st->private_key, 32);
        memcpy(st->public_key, from_st->public_key, 32);
    } else if (from->key_type == NOISE_KEY_TYPE_PUBLIC) {
        memcpy(st->public_key, from_st->public_key, 32);
    }
    return NOISE_ERROR_NONE;
}

static int noise_curve25519_calculate
    (const NoiseDHState *private_key_state,
     const NoiseDHState *public_key_state,
     uint8_t *shared_key)
{
    const NoiseCurve25519State *priv_st = (const NoiseCurve25519State *)private_key_state;
    const NoiseCurve25519State *pub_st = (const NoiseCurve25519State *)public_key_state;
    mbedtls_ecdh_context ecdh;
    mbedtls_ecp_keypair keypair;
    int ret;
    
    mbedtls_ecdh_init(&ecdh);
    mbedtls_ecp_keypair_init(&keypair);
    
    /* Setup Curve25519 */
    ret = mbedtls_ecdh_setup(&ecdh, MBEDTLS_ECP_DP_CURVE25519);
    if (ret != 0)
        goto cleanup;
    
    /* Setup our keypair */
    ret = mbedtls_ecp_group_load(&keypair.grp, MBEDTLS_ECP_DP_CURVE25519);
    if (ret != 0)
        goto cleanup;
        
    ret = mbedtls_mpi_read_binary(&keypair.d, priv_st->private_key, 32);
    if (ret != 0)
        goto cleanup;
    
    /* We don't need to set the public key Q for ECDH calculation */
    ret = mbedtls_ecdh_get_params(&ecdh, &keypair, MBEDTLS_ECDH_OURS);
    if (ret != 0)
        goto cleanup;
    
    /* Import peer's public key */
    ret = mbedtls_ecdh_read_public(&ecdh, pub_st->public_key, 32);
    if (ret != 0)
        goto cleanup;
    
    /* Compute shared secret */
    size_t olen;
    ret = mbedtls_ecdh_calc_secret(&ecdh, &olen, shared_key, 32, NULL, NULL);
    if (ret != 0)
        goto cleanup;
    
    /* Verify we got 32 bytes */
    if (olen != 32) {
        ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
        goto cleanup;
    }
    
cleanup:
    mbedtls_ecp_keypair_free(&keypair);
    mbedtls_ecdh_free(&ecdh);
    
    /* Always return success to avoid timing attacks */
    if (ret != 0)
        memset(shared_key, 0, 32);
    return NOISE_ERROR_NONE;
}

NoiseDHState *noise_curve25519_new(void)
{
    NoiseCurve25519State *state = noise_new(NoiseCurve25519State);
    if (!state)
        return 0;
    state->parent.dh_id = NOISE_DH_CURVE25519;
    state->parent.ephemeral_only = 0;
    state->parent.nulls_allowed = 1;
    state->parent.private_key_len = 32;
    state->parent.public_key_len = 32;
    state->parent.shared_key_len = 32;
    state->parent.private_key = state->private_key;
    state->parent.public_key = state->public_key;
    state->parent.generate_keypair = noise_curve25519_generate_keypair;
    state->parent.set_keypair = noise_curve25519_set_keypair;
    state->parent.set_keypair_private = noise_curve25519_set_keypair_private;
    state->parent.validate_public_key = noise_curve25519_validate_public_key;
    state->parent.copy = noise_curve25519_copy;
    state->parent.calculate = noise_curve25519_calculate;
    return &(state->parent);
}

#endif  // NOISE_USE_MBEDTLS && NOISE_USE_CURVE25519