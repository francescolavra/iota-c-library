#include <string.h>
#include <stdio.h>

#include "addresses.h"
#include "common.h"
#include "conversion.h"
#include "kerl.h"

#define CHECKSUM_CHARS 9

static void digest_single_chunk(unsigned char *key_fragment,
                                cx_sha3_t *digest_sha3, cx_sha3_t *round_sha3)
{
    int k;

    for (k = 0; k < 26; k++) {
        kerl_initialize(round_sha3);
        kerl_absorb_chunk(round_sha3, key_fragment);
        kerl_squeeze_final_chunk(round_sha3, key_fragment);
    }

    // absorb buffer directly to avoid storing the digest fragment
    kerl_absorb_chunk(digest_sha3, key_fragment);
}



// initialize the sha3 instance for generating private key
static void init_shas(const unsigned char *seed_bytes, uint32_t idx,
                      cx_sha3_t *key_sha, cx_sha3_t *digest_sha)
{
    // use temp bigint so seed not destroyed
    unsigned char bytes[NUM_HASH_BYTES];
    memcpy(bytes, seed_bytes, sizeof(bytes));

    bytes_add_u32_mem(bytes, idx);

    kerl_initialize(key_sha);
    kerl_absorb_chunk(key_sha, bytes);
    kerl_squeeze_final_chunk(key_sha, bytes);

    kerl_initialize(key_sha);
    kerl_absorb_chunk(key_sha, bytes);

    kerl_initialize(digest_sha);
}

// generate public address in byte format
void get_public_addr(const unsigned char *seed_bytes, uint32_t idx,
                     unsigned int security, unsigned char *address_bytes)
{
    cx_sha3_t key_sha, digest_sha;

    get_public_addr_mem(seed_bytes, idx, security, address_bytes, &key_sha,
        &digest_sha);
}

void get_public_addr_mem(const unsigned char *seed_bytes, uint32_t idx,
                         unsigned int security, unsigned char *address_bytes,
                         cx_sha3_t *key_sha, cx_sha3_t *digest_sha)
{
    if (!in_range(security, MIN_SECURITY_LEVEL, MAX_SECURITY_LEVEL)) {
        THROW(INVALID_PARAMETER);
    }

    // init private key sha, digest sha
    init_shas(seed_bytes, idx, key_sha, digest_sha);

    // buffer for the digests of each security level
    unsigned char digest[NUM_HASH_BYTES * security];

    // only store a single fragment of the private key at a time
    // use last chunk of buffer, as this is only used after the key is generated
    unsigned char *key_f = digest + NUM_HASH_BYTES * (security - 1);
    
    uint8_t i, j;

    for (i = 0; i < security; i++) {
        for (j = 0; j < 27; j++) {
            // use address output array as a temp Kerl state storage
            unsigned char *state = address_bytes;

            // the state takes only 48bytes and allows us to reuse key_sha
            kerl_state_squeeze_chunk(key_sha, state, key_f);
            // re-use key_sha as round_sha
            digest_single_chunk(key_f, digest_sha, key_sha);

            // as key_sha has been tainted, reinitialize with the saved state
            kerl_reinitialize(key_sha, state);
        }
        kerl_squeeze_final_chunk(digest_sha, digest + NUM_HASH_BYTES * i);

        // reset digest sha for next digest
        kerl_initialize(digest_sha);
    }

    // absorb the digest for each security
    kerl_absorb_bytes(digest_sha, digest, NUM_HASH_BYTES * security);

    // one final squeeze for address
    kerl_squeeze_final_chunk(digest_sha, address_bytes);
}

// get 9 character checksum of NUM_HASH_TRYTES character address
void get_address_with_checksum(const unsigned char *address_bytes,
                               char *full_address)
{
    cx_sha3_t sha;
    get_address_with_checksum_mem(address_bytes, full_address, &sha);
}

void get_address_with_checksum_mem(const unsigned char *address_bytes,
                                   char *full_address, cx_sha3_t *sha)
{
    kerl_initialize(sha);

    unsigned char checksum_bytes[NUM_HASH_BYTES];
    kerl_absorb_chunk(sha, address_bytes);
    kerl_squeeze_final_chunk(sha, checksum_bytes);

    char full_checksum[NUM_HASH_TRYTES];
    bytes_to_chars(checksum_bytes, full_checksum, NUM_HASH_BYTES);

    bytes_to_chars(address_bytes, full_address, NUM_HASH_BYTES);

    memcpy(full_address + NUM_HASH_TRYTES,
              full_checksum + NUM_HASH_TRYTES - CHECKSUM_CHARS, CHECKSUM_CHARS);
}

int address_verify_checksum(const char *full_address)
{
    unsigned char addr_bytes[NUM_HASH_BYTES];
    char addr_with_cksum[NUM_HASH_TRYTES + NUM_ADDR_CKSUM_TRYTES];

    chars_to_bytes(full_address, addr_bytes, NUM_HASH_TRYTES);
    get_address_with_checksum(addr_bytes, addr_with_cksum);
    if (!memcmp(full_address + NUM_HASH_TRYTES,
            addr_with_cksum + NUM_HASH_TRYTES, NUM_ADDR_CKSUM_TRYTES)) {
        return 0;
    }
    else {
        return -1;
    }
}

int address_verify_checksum_mem(const char *full_address, cx_sha3_t *sha)
{
    unsigned char addr_bytes[NUM_HASH_BYTES];
    char addr_with_cksum[NUM_HASH_TRYTES + NUM_ADDR_CKSUM_TRYTES];

    chars_to_bytes(full_address, addr_bytes, NUM_HASH_TRYTES);
    get_address_with_checksum_mem(addr_bytes, addr_with_cksum, sha);
    if (!memcmp(full_address + NUM_HASH_TRYTES,
            addr_with_cksum + NUM_HASH_TRYTES, NUM_ADDR_CKSUM_TRYTES)) {
        return 0;
    }
    else {
        return -1;
    }
}
