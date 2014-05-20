#ifndef _STR_H_
#define _STR_H_

#include <stdlib.h>
#include <string.h>

typedef struct
{
    char*   ptr;
    size_t  len;
} str_t;

#define str_free(str) \
do { \
    str_t _str; \
    (void)(&str == &_str); \
    if (str.len && str.ptr) free(str.ptr); \
} while(0)

#define str_ptr_free(str) \
do { \
    typeof(*str) tmp = (str); \
    str_t _str; \
    (void)(&tmp == &_str); \
    if (str->len && str->ptr) free(str->ptr); \
    free(str); \
} while(0)

inline str_t str_dup(const char* ptr)
{
    size_t len = strlen(ptr);
    str_t ret = {malloc(len + 1), len};
    memcpy(ret.ptr, ptr, len);
    ret.ptr[len] = 0;
    return ret;
}

#endif

