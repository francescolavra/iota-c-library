cmake_minimum_required(VERSION 3.0)
project(c_light_wallet)

set(CMAKE_C_STANDARD 99)

set(SOURCE_FILES
        src/iota/addresses.c
        src/iota/addresses.h
        src/iota/bundle.c
        src/iota/bundle.h
        src/iota/signing.c
        src/iota/signing.h
        src/iota/common.h
		src/iota/common.c
        src/iota/conversion.c
        src/iota/conversion.h
        src/iota/iota_types.h
        src/iota/kerl.c
        src/iota/kerl.h
		src/iota/transfers.h
		src/iota/transfers.c
        src/keccak/macros.h
        src/keccak/options.h
        src/keccak/sha3.c
        src/keccak/sha3.h
        src/utils.c
        src/utils.h
		)

add_library(iota_wallet STATIC ${SOURCE_FILES})
