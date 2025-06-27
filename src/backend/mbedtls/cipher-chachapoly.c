#include "noise/defines.h"
#if NOISE_USE_MBEDTLS && NOISE_USE_CHACHAPOLY

#include "protocol/internal.h"
#include <mbedtls/chachapoly.h>
#include <mbedtls/chacha20.h>
#include <mbedtls/poly1305.h>
#include <string.h>

typedef struct
{
    struct NoiseCipherState_s parent;
    mbedtls_chachapoly_context ctx;

} NoiseChaChaPolyState;

static void noise_chachapoly_init_key
    (NoiseCipherState *state, const uint8_t *key)
{
    NoiseChaChaPolyState *st = (NoiseChaChaPolyState *)state;
    mbedtls_chachapoly_setkey(&st->ctx, key);
}

#define PUT_UINT64_LE(buf, value) \
    do { \
        (buf)[0] = (uint8_t)(value); \
        (buf)[1] = (uint8_t)((value) >> 8); \
        (buf)[2] = (uint8_t)((value) >> 16); \
        (buf)[3] = (uint8_t)((value) >> 24); \
        (buf)[4] = (uint8_t)((value) >> 32); \
        (buf)[5] = (uint8_t)((value) >> 40); \
        (buf)[6] = (uint8_t)((value) >> 48); \
        (buf)[7] = (uint8_t)((value) >> 56); \
    } while (0)

static int noise_chachapoly_encrypt
    (NoiseCipherState *state, const uint8_t *ad, size_t ad_len,
     uint8_t *data, size_t len)
{
    NoiseChaChaPolyState *st = (NoiseChaChaPolyState *)state;
    uint8_t nonce[12];
    int ret;

    /* Build the 96-bit nonce: 32 bits of zeros + 64-bit counter */
    memset(nonce, 0, 4);
    PUT_UINT64_LE(nonce + 4, state->n);

    /* Perform AEAD encryption */
    ret = mbedtls_chachapoly_encrypt_and_tag(&st->ctx, len, nonce, ad, ad_len,
                                             data, data, data + len);
    
    if (ret != 0)
        return NOISE_ERROR_SYSTEM;
    
    return NOISE_ERROR_NONE;
}

static int noise_chachapoly_decrypt
    (NoiseCipherState *state, const uint8_t *ad, size_t ad_len,
     uint8_t *data, size_t len)
{
    NoiseChaChaPolyState *st = (NoiseChaChaPolyState *)state;
    uint8_t nonce[12];
    int ret;

    /* Build the 96-bit nonce: 32 bits of zeros + 64-bit counter */
    memset(nonce, 0, 4);
    PUT_UINT64_LE(nonce + 4, state->n);

    /* Perform AEAD decryption */
    ret = mbedtls_chachapoly_auth_decrypt(&st->ctx, len, nonce, ad, ad_len,
                                          data + len, data, data);
    
    if (ret != 0)
        return NOISE_ERROR_MAC_FAILURE;
    
    return NOISE_ERROR_NONE;
}

static void noise_chachapoly_free(NoiseCipherState *state)
{
    NoiseChaChaPolyState *st = (NoiseChaChaPolyState *)state;
    mbedtls_chachapoly_free(&st->ctx);
}

NoiseCipherState *noise_chachapoly_new(void)
{
    NoiseChaChaPolyState *state = noise_new(NoiseChaChaPolyState);
    if (!state)
        return 0;
    
    /* Initialize the mbedTLS context */
    mbedtls_chachapoly_init(&state->ctx);
    
    state->parent.cipher_id = NOISE_CIPHER_CHACHAPOLY;
    state->parent.key_len = 32;
    state->parent.mac_len = 16;
    state->parent.create = noise_chachapoly_new;
    state->parent.init_key = noise_chachapoly_init_key;
    state->parent.encrypt = noise_chachapoly_encrypt;
    state->parent.decrypt = noise_chachapoly_decrypt;
    state->parent.destroy = noise_chachapoly_free;
    return &(state->parent);
}

#endif  // NOISE_USE_MBEDTLS && NOISE_USE_CHACHAPOLY