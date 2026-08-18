/*
 * Copyright (C) 2016 Southern Storm Software, Pty Ltd.
 * Copyright (C) 2016 Topology LP.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#include "noise/defines.h"
#if NOISE_USE_LIBSODIUM

#include "protocol/internal.h"
#include <sodium.h>
#include <string.h>

#if defined(__has_include)
# if __has_include(<sodium/sodium_esphome.h>)
#  include <sodium/sodium_esphome.h>
# endif
#endif

#if defined(SODIUM_ESPHOME_NOISE_FAST_PATH) && \
    SODIUM_ESPHOME_NOISE_FAST_PATH == 1 && \
    !defined(NOISE_DISABLE_SODIUM_FAST_PATH)

/*
 * Fast path for the esphome libsodium port: the ChaCha20 key schedule is
 * loaded once per session, the Poly1305 key block and the payload share one
 * cipher pass, and the whole MAC transcript is one call. The aead_mac
 * entry point accepts a NULL ad when ad_len is 0, so the ad branch needs
 * no guard here, and block0_xor accepts NULL in and out pointers when len
 * is 0, deriving only the key block and leaving the counter at 1 for the
 * decrypt payload pass.
 *
 * To exercise this path off target, add_subdirectory this repo and the
 * esphome libsodium port (patches applied) into one CMake build; the port
 * exports the `sodium` target this repo links, and the cipherstate unit
 * test then runs the RFC 7539 vector through the fast path.
 *
 * SODIUM_ESPHOME_NOISE_FAST_PATH is a version number; the port bumps it if
 * the semantics of the session entry points ever change, and the exact
 * match above downgrades this file to the fallback until it is updated
 * for the new semantics on purpose. Define NOISE_DISABLE_SODIUM_FAST_PATH
 * to force the fallback.
 */

typedef struct
{
    struct NoiseCipherState_s parent;
    /* Session persistent ChaCha20 key schedule; loaded once per key, only
       the nonce and counter words are rewritten per message. */
    crypto_stream_chacha20_ietf_session_state chacha_st;
} NoiseChaChaPolyState;

static void noise_chachapoly_init_key
    (NoiseCipherState *state, const uint8_t *key)
{
    NoiseChaChaPolyState *st = (NoiseChaChaPolyState *)state;
    crypto_stream_chacha20_ietf_session_init(&(st->chacha_st), key);
}

static int noise_chachapoly_encrypt
    (NoiseCipherState *state, const uint8_t *ad, size_t ad_len,
     uint8_t *data, size_t len)
{
    NoiseChaChaPolyState *st = (NoiseChaChaPolyState *)state;
    uint8_t block[64] __attribute__((aligned(4)));

    /* Poly1305 key generation and payload encryption share one cipher
       setup; the key in block is cleared as soon as the MAC is done */
    crypto_stream_chacha20_ietf_session_block0_xor
        (&(st->chacha_st), block, data, data, len, state->n);
    crypto_onetimeauth_poly1305_aead_mac
        (data + len, ad, ad_len, data, len, block);
    sodium_memzero(block, 32);
    return NOISE_ERROR_NONE;
}

static int noise_chachapoly_decrypt
    (NoiseCipherState *state, const uint8_t *ad, size_t ad_len,
     uint8_t *data, size_t len)
{
    NoiseChaChaPolyState *st = (NoiseChaChaPolyState *)state;
    uint8_t block[64] __attribute__((aligned(4)));
    uint8_t mac[16];

    crypto_stream_chacha20_ietf_session_block0_xor
        (&(st->chacha_st), block, NULL, NULL, 0, state->n);
    crypto_onetimeauth_poly1305_aead_mac(mac, ad, ad_len, data, len, block);
    sodium_memzero(block, 32);
    if (!noise_is_equal(mac, data + len, 16)) {
        /* the computed tag is valid for a nonce that stays live, since n
           is not incremented on MAC failure */
        sodium_memzero(mac, 16);
        return NOISE_ERROR_MAC_FAILURE;
    }
    /* The session state's block counter is already at 1 after the key
       generation call above */
    crypto_stream_chacha20_ietf_session_xor(&(st->chacha_st), data, data, len);
    return NOISE_ERROR_NONE;
}

#else /* stock libsodium fallback */

typedef struct
{
    struct NoiseCipherState_s parent;
    uint8_t chacha_k[crypto_stream_chacha20_KEYBYTES];
} NoiseChaChaPolyState;

/*
 * Per-operation working state. Only the key and nonce counter persist
 * between calls, so this lives on the stack during encrypt/decrypt.
 * Keeping it out of NoiseChaChaPolyState shrinks each long-lived cipher
 * state by over 300 bytes, which matters on embedded targets that hold
 * two cipher states per connection. The trade is ~336 bytes of stack for
 * the duration of each call, below what the curve25519 handshake steps
 * already require.
 *
 * The scratch is not bulk wiped on return; a full wipe measured 9 to 13
 * percent of a small message operation. Instead the secrets are cleared
 * at the point they die: the Poly1305 key right after state init in
 * setup(), and on decrypt failure the computed tag (its nonce stays
 * live because n is not incremented on error). What remains after
 * return is public or unused keystream, and libsodium wipes the
 * poly1305 state inside crypto_onetimeauth_poly1305_final.
 */
typedef struct
{
    uint8_t chacha_n[crypto_stream_chacha20_IETF_NONCEBYTES];
    crypto_onetimeauth_poly1305_state poly1305;
    uint8_t block[64];
} NoiseChaChaPolyScratch;

static void noise_chachapoly_init_key
    (NoiseCipherState *state, const uint8_t *key)
{
    NoiseChaChaPolyState *st = (NoiseChaChaPolyState *)state;
    memcpy(st->chacha_k, key, crypto_stream_chacha20_KEYBYTES);
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

/**
 * \brief Sets up a ChaChaPoly scratch area to encrypt/decrypt a block.
 *
 * \param st The encryption state for ChaChaPoly.
 * \param sc The stack scratch area for this operation.
 * \param n The nonce for this block.
 */
static void noise_chachapoly_setup
    (const NoiseChaChaPolyState *st, NoiseChaChaPolyScratch *sc, uint64_t n)
{
    /* The 96-bit nonce is formed by encoding 32 bits of zeros followed by little-endian encoding of n */
    memset(sc->chacha_n, 0, 4);
    PUT_UINT64_LE(sc->chacha_n + 4, n);

    /* Encrypt an initial block to create the Poly1305 key. (memset + _xor of a
       full block benchmarks faster here than generating 32 keystream bytes
       with crypto_stream_chacha20_ietf.) */
    memset(sc->block, 0, 64);
    crypto_stream_chacha20_ietf_xor(sc->block, sc->block, 64, sc->chacha_n, st->chacha_k);
    crypto_onetimeauth_poly1305_init(&(sc->poly1305), sc->block);
    /* The Poly1305 key is dead once the state is initialized; clear it so
       the frame releases without key material. This matches the ref
       backend's clear-in-setup approach at a tenth of the cost of the
       full scratch wipe this file used to do; the remaining 32 bytes are
       discarded counter-0 keystream. */
    sodium_memzero(sc->block, 32);
}

/**
 * \brief Pads the Poly1305 input to a multiple of 16 bytes.
 *
 * \param sc The stack scratch area for this operation.
 * \param len The length of the input that needs to be padded.
 */
static void noise_chachapoly_pad_auth(NoiseChaChaPolyScratch *sc, size_t len)
{
    len %= 16;
    if (len) {
        static uint8_t const padding[16] = {
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        };
        crypto_onetimeauth_poly1305_update(&(sc->poly1305), padding, 16 - len);
    }
}

/**
 * \brief Finalize the Poly1305 hash by adding the lengths.
 *
 * \param sc The stack scratch area for this operation.
 * \param ad_len The length of the associated data.
 * \param data_len The length of the ciphertext.
 */
static void noise_chachapoly_auth_lengths
    (NoiseChaChaPolyScratch *sc, uint64_t ad_len, uint64_t data_len)
{
    PUT_UINT64_LE(sc->block, ad_len);
    PUT_UINT64_LE(sc->block + 8, data_len);
    crypto_onetimeauth_poly1305_update(&(sc->poly1305), sc->block, 16);
}

static int noise_chachapoly_encrypt
    (NoiseCipherState *state, const uint8_t *ad, size_t ad_len,
     uint8_t *data, size_t len)
{
    NoiseChaChaPolyState *st = (NoiseChaChaPolyState *)state;
    NoiseChaChaPolyScratch sc;
    noise_chachapoly_setup(st, &sc, state->n);
    if (ad_len) {
        crypto_onetimeauth_poly1305_update(&(sc.poly1305), ad, ad_len);
        noise_chachapoly_pad_auth(&sc, ad_len);
    }
    crypto_stream_chacha20_ietf_xor_ic(data, data, len, sc.chacha_n, 1U, st->chacha_k);
    crypto_onetimeauth_poly1305_update(&(sc.poly1305), data, len);
    noise_chachapoly_pad_auth(&sc, len);
    noise_chachapoly_auth_lengths(&sc, ad_len, len);
    crypto_onetimeauth_poly1305_final(&(sc.poly1305), data + len);
    return NOISE_ERROR_NONE;
}

static int noise_chachapoly_decrypt
    (NoiseCipherState *state, const uint8_t *ad, size_t ad_len,
     uint8_t *data, size_t len)
{
    NoiseChaChaPolyState *st = (NoiseChaChaPolyState *)state;
    NoiseChaChaPolyScratch sc;
    int ok;
    noise_chachapoly_setup(st, &sc, state->n);
    if (ad_len) {
        crypto_onetimeauth_poly1305_update(&(sc.poly1305), ad, ad_len);
        noise_chachapoly_pad_auth(&sc, ad_len);
    }
    crypto_onetimeauth_poly1305_update(&(sc.poly1305), data, len);
    noise_chachapoly_pad_auth(&sc, len);
    noise_chachapoly_auth_lengths(&sc, ad_len, len);
    crypto_onetimeauth_poly1305_final(&(sc.poly1305), sc.block);
    ok = noise_is_equal(sc.block, data + len, 16);
    if (!ok) {
        /* the computed tag is valid for a nonce that stays live, since n
           is not incremented on MAC failure */
        sodium_memzero(sc.block, 16);
        return NOISE_ERROR_MAC_FAILURE;
    }
    crypto_stream_chacha20_ietf_xor_ic(data, data, len, sc.chacha_n, 1U, st->chacha_k);
    return NOISE_ERROR_NONE;
}

#endif /* stock libsodium fallback */

NoiseCipherState *noise_chachapoly_new(void)
{
    NoiseChaChaPolyState *state = noise_new(NoiseChaChaPolyState);
    if (!state)
        return 0;
    state->parent.cipher_id = NOISE_CIPHER_CHACHAPOLY;
    state->parent.key_len = crypto_stream_chacha20_KEYBYTES;
    state->parent.mac_len = crypto_onetimeauth_poly1305_BYTES;
    state->parent.create = noise_chachapoly_new;
    state->parent.init_key = noise_chachapoly_init_key;
    state->parent.encrypt = noise_chachapoly_encrypt;
    state->parent.decrypt = noise_chachapoly_decrypt;
    return &(state->parent);
}

#endif  // NOISE_USE_LIBSODIUM
