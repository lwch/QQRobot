#include <string.h>

#include "str.h"

str_t static_empty_str = empty_str;

str_t str_dup(const char* ptr)
{
    size_t len = strlen(ptr);
    if (len == 0) return static_empty_str;
    str_t ret = {malloc(len + 1), len};
    memcpy(ret.ptr, ptr, len);
    ret.ptr[len] = 0;
    return ret;
}

inline str_t str_from(const char* ptr)
{
    str_t ret;
    ret.ptr = (char*)ptr;
    ret.len = strlen(ptr);
    return ret;
}

void str_array_free(str_t* array, size_t count)
{
    size_t i;
    for (i = 0; i < count; ++i)
    {
        free(array[i].ptr);
    }
}

