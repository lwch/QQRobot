#ifndef _STRUCT_H_
#define _STRUCT_H_

#include <stdlib.h>
#include "str.h"

typedef struct
{
    char*   ptr;
    size_t  len;
    size_t  capacity;
} curl_data_t;

typedef struct
{
    char**  keys;
    char**  vals;
    size_t  count;
} curl_header_t;

typedef struct
{
    char**  keys;
    char**  vals;
    size_t  count;
} cookie_t;

typedef struct
{
    str_t*  keys;
    str_t*  vals;
    size_t  count;
} pair_array_t;

extern pair_array_t static_empty_pair_array;

#define empty_pair_array {NULL, NULL, 0}

extern void pair_array_free(pair_array_t* array);
extern void pair_array_append_pointers(pair_array_t* array, const char* key, const char* val);
extern void pair_array_append_empty_value(pair_array_t* array, const char* key);
extern str_t pair_array_lookup(pair_array_t* array, str_t key);

#endif

