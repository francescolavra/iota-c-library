#ifndef ADDRESSES_H
#define ADDRESSES_H

#include "common.h"
#include "iota_types.h"

void get_public_addr(const unsigned char *seed_bytes, uint32_t idx,
                     unsigned int security, unsigned char *address_bytes);
void get_public_addr_mem(const unsigned char *seed_bytes, uint32_t idx,
                         unsigned int security, unsigned char *address_bytes,
                         cx_sha3_t *key_sha, cx_sha3_t *digest_sha);

/** @brief Computes the full address string in base-27 encoding.
 *  The full address consists of the actual address (81 chars) plus 9 chars of
 *  checksum.
 */
void get_address_with_checksum(const unsigned char *address_bytes,
                               char *full_address);
void get_address_with_checksum_mem(const unsigned char *address_bytes,
                                   char *full_address, cx_sha3_t *sha);

int address_verify_checksum(const char *full_address);
int address_verify_checksum_mem(const char *full_address, cx_sha3_t *sha);

#endif // ADDRESSES_H
