#include "noise/defines.h"
#if NOISE_USE_MBEDTLS && NOISE_USE_SHA256

#include "protocol/internal.h"
#include <mbedtls/sha256.h>
#include <string.h>

typedef struct
{
    struct NoiseHashState_s parent;
    mbedtls_sha256_context sha256;
} NoiseSHA256State;

static void noise_sha256_reset(NoiseHashState *state)
{
    NoiseSHA256State *st = (NoiseSHA256State *)state;
    mbedtls_sha256_init(&(st->sha256));
    mbedtls_sha256_starts(&(st->sha256), 0); /* 0 = SHA-256, not SHA-224 */
}

static void noise_sha256_update(NoiseHashState *state, const uint8_t *data, size_t len)
{
    NoiseSHA256State *st = (NoiseSHA256State *)state;
    mbedtls_sha256_update(&(st->sha256), data, len);
}

static void noise_sha256_finalize(NoiseHashState *state, uint8_t *hash)
{
    NoiseSHA256State *st = (NoiseSHA256State *)state;
    mbedtls_sha256_finish(&(st->sha256), hash);
}

static void noise_sha256_destroy(NoiseHashState *state)
{
    NoiseSHA256State *st = (NoiseSHA256State *)state;
    mbedtls_sha256_free(&(st->sha256));
}

NoiseHashState *noise_sha256_new(void)
{
    NoiseSHA256State *state = noise_new(NoiseSHA256State);
    if (!state)
        return 0;
    state->parent.hash_id = NOISE_HASH_SHA256;
    state->parent.hash_len = 32;
    state->parent.block_len = 64;
    state->parent.reset = noise_sha256_reset;
    state->parent.update = noise_sha256_update;
    state->parent.finalize = noise_sha256_finalize;
    state->parent.destroy = noise_sha256_destroy;
    return &(state->parent);
}

#endif  // NOISE_USE_MBEDTLS && NOISE_USE_SHA256