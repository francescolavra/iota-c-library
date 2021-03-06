#ifndef IOTA_TYPES_H
#define IOTA_TYPES_H

#include <stdint.h>

typedef int8_t trit_t;
typedef int8_t tryte_t;

#define MIN_TRIT_VALUE -1
#define MAX_TRIT_VALUE 1

#define MIN_TRYTE_VALUE -13
#define MAX_TRYTE_VALUE 13

#define MAX_IOTA_VALUE INT64_C(2779530283277761) // (3^33-1) / 2

#define MIN_SECURITY_LEVEL 1
#define MAX_SECURITY_LEVEL 3

#define NUM_HASH_TRITS 243
#define NUM_HASH_TRYTES 81
#define NUM_HASH_BYTES (CX_KECCAK384_SIZE)

#define NUM_ADDR_TRITS 243
#define NUM_ADDR_TRYTES 81

#define NUM_ADDR_CKSUM_TRITS 27
#define NUM_ADDR_CKSUM_TRYTES 9

#define NUM_TRANSACTION_TRITS 8019
#define NUM_TRANSACTION_TRYTES 2673

#define NUM_SIG_MSG_TRITS 6561
#define NUM_SIG_MSG_TRYTES 2187

#define NUM_TAG_TRITS 81
#define NUM_TAG_TRYTES 27

#define NUM_NONCE_TRITS 81
#define NUM_NONCE_TRYTES 27

#endif // IOTA_TYPES_H
