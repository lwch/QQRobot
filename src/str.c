#include <auto_config.h>

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

str_t str_ndup(const char* ptr, size_t len)
{
    if (len == 0) return static_empty_str;
    str_t ret = {malloc(len + 1), len};
    memcpy(ret.ptr, ptr, len);
    ret.ptr[len] = 0;
    return ret;
}

void str_cpy(str_t* dst, const str_t src)
{
    if (dst->ptr) free(dst->ptr);
    dst->ptr = malloc(src.len + 1);
    memcpy(dst->ptr, src.ptr, src.len);
    dst->ptr[src.len] = 0;
    dst->len = src.len;
}

void str_cat(str_t* str, const char* ptr)
{
    size_t len = strlen(ptr);
    str->ptr = realloc(str->ptr, str->len + len + 1);
    memcpy(str->ptr + str->len, ptr, len);
    str->ptr[str->len + len] = 0;
    str->len += len;
}

void str_ncat(str_t* str, const char* ptr, size_t len)
{
    str->ptr = realloc(str->ptr, str->len + len + 1);
    memcpy(str->ptr + str->len, ptr, len);
    str->ptr[str->len + len] = 0;
    str->len += len;
}

inline str_t str_from(const char* ptr)
{
    str_t ret;
    ret.ptr = (char*)ptr;
    ret.len = strlen(ptr);
    return ret;
}

str_t str2bin(const str_t str)
{
    str_t ret = {malloc((str.len >> 1) + 1), str.len >> 1};
    size_t i;
    for (i = 0; i < ret.len; ++i)
    {
        unsigned char ch1 = tolower(str.ptr[(i << 1)    ]);
        unsigned char ch2 = tolower(str.ptr[(i << 1) + 1]);

        ch1 = (ch1 >= 'a' && ch1 <= 'f') ? ch1 - 'a' + 10 : ch1 - '0';
        ch2 = (ch2 >= 'a' && ch2 <= 'f') ? ch2 - 'a' + 10 : ch2 - '0';
        ret.ptr[i] = (ch1 << 4) | ch2;
    }
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

