#ifndef _STRUCT_H_
#define _STRUCT_H_

#include <stdlib.h>

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

#endif

