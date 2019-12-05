#include "utils.h"
#include <string.h>
#include "iota/common.h"

#define PAD_CHAR '9'

bool validate_chars(const char *chars, unsigned int num_chars)
{
    const size_t len = common_strnlen(chars, num_chars);
    unsigned int i;
    for (i = 0; i < len; i++) {
        const char c = chars[i];
        if (c != '9' && (c < 'A' || c > 'Z')) {
            return false;
        }
    }

    return true;
}

void rpad_chars(char *destination, const char *source, unsigned int num_chars)
{
    const size_t len = common_strnlen(source, num_chars);
    memcpy(destination, source, len);
    memset(destination + len, PAD_CHAR, num_chars - len);
}
