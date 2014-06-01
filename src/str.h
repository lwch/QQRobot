#ifndef _STR_H_
#define _STR_H_

#include <stdlib.h>

typedef struct
{
    char*   ptr;
    size_t  len;
} str_t;

extern str_t static_empty_str;

#define str(ptr) {ptr, sizeof(ptr) - 1}
#define empty_str {NULL, 0}

#define str_free(str) \
do { \
    str_t _str; \
    (void)(&(str) == &_str); \
    if ((str).len && (str).ptr) free((str).ptr); \
    (str).ptr = NULL; \
    (str).len = 0; \
} while(0)

#define str_ptr_free(str) \
do { \
    typeof(*(str)) tmp = (str); \
    str_t _str; \
    (void)(&tmp == &_str); \
    if ((str)->len && (str)->ptr) free((str)->ptr); \
    free(str); \
} while(0)

#define str_empty(str) (str.len == 0)

extern str_t str_dup(const char* ptr);
extern str_t str_ndup(const char* ptr, size_t len);
extern void str_cpy(str_t* dst, const str_t src);
extern void str_cat(str_t* str, const char* ptr);
extern void str_ncat(str_t* str, const char* ptr, size_t len);
extern str_t str_from(const char* ptr);

extern str_t str2bin(const str_t str);

extern void str_array_free(str_t* array, size_t count);

#endif

