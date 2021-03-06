#include "signing.h"
#include "common.h"
#include "conversion.h"
#include "kerl.h"

static void initialize_state(const unsigned char *seed_bytes,
                             uint32_t address_idx, unsigned char *state)
{
    memcpy(state, seed_bytes, 48);
    bytes_add_u32_mem(state, address_idx);

    cx_sha3_t sha;
    kerl_initialize(&sha);
    kerl_absorb_chunk(&sha, state);
    kerl_squeeze_final_chunk(&sha, state);
}

void signing_initialize(SIGNING_CTX *ctx, const unsigned char *seed_bytes,
                        uint32_t address_idx, uint8_t security,
                        const tryte_t *normalized_hash)
{
    initialize_state(seed_bytes, address_idx, ctx->state);
    ctx->fragment_index = 0;
    ctx->last_fragment = NUM_SIGNATURE_FRAGMENTS(security) - 1;

    memcpy(ctx->hash, normalized_hash, NUM_HASH_TRYTES);
}

static void generate_signature_fragment(unsigned char *state,
                                        const tryte_t *hash_fragment,
                                        unsigned char *signature_bytes)
{
    cx_sha3_t sha;
    unsigned int j, k;
    kerl_reinitialize(&sha, state);

    for (j = 0; j < SIGNATURE_FRAGMENT_SIZE; j++) {
        unsigned char *signature_f = signature_bytes + j * NUM_HASH_BYTES;

        // the output of the squeeze is exactly the private key
        kerl_state_squeeze_chunk(&sha, state, signature_f);

        for (k = MAX_TRYTE_VALUE - hash_fragment[j]; k-- > 0;) {
            kerl_initialize(&sha);
            kerl_absorb_chunk(&sha, signature_f);
            kerl_squeeze_final_chunk(&sha, signature_f);
        }

        // if we are not the the final iteration reinitialize to get next key_f
        if (j < SIGNATURE_FRAGMENT_SIZE - 1) {
            kerl_reinitialize(&sha, state);
        }
    }
}

unsigned int signing_next_fragment(SIGNING_CTX *ctx,
                                   unsigned char *signature_bytes)
{
    if (!signing_has_next_fragment(ctx)) {
        THROW(INVALID_STATE);
    }

    generate_signature_fragment(
        ctx->state, ctx->hash + ctx->fragment_index * SIGNATURE_FRAGMENT_SIZE,
        signature_bytes);

    return ctx->fragment_index++;
}
