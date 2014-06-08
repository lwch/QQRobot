#ifndef _CONF_MODULE_H_
#define _CONF_MODULE_H_

#include <stdlib.h>

#include "str.h"

typedef str_t conf_key_t;

typedef struct
{
    enum
    {
        CONF_VALUE_TYPE_NONE = 0,
        CONF_VALUE_TYPE_BOOL = 1,
        CONF_VALUE_TYPE_STRING = 2,
        CONF_VALUE_TYPE_ARRAY = 3,
    } type;

    union
    {
        uchar   bval;
        str_t   string;
        struct
        {
            str_t*  array;
            size_t  count;
        } array;
    };
} conf_val_t;
#define empty_conf_value {CONF_VALUE_TYPE_NONE, {0}}

typedef struct
{
    conf_key_t*  keys;
    conf_val_t*  vals;
    size_t       count;
} conf_t;
extern conf_t static_empty_conf;
#define empty_conf {NULL, NULL, 0}

extern int parse_conf_file(str_t path);

extern conf_val_t conf_lookup(conf_t* conf, str_t key);
extern void conf_append_bool(conf_t* conf, const char* key, uchar val);
extern void conf_append_strs(conf_t* conf, const char* key, const char* val);
extern void conf_append_array_ref(conf_t* conf, const char* key, str_t* array, size_t count);
extern void conf_append_empty_value(conf_t* conf, const char* key);

#endif

