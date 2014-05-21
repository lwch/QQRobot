#include <string.h>

#include "str.h"

str_t str_dup(const char* ptr)
{
    size_t len = strlen(ptr);
    str_t ret = {malloc(len + 1), len};
    memcpy(ret.ptr, ptr, len);
    ret.ptr[len] = 0;
    return ret;
}

