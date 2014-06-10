#ifndef _STRUCT_H_
#define _STRUCT_H_

#include <stdlib.h>

#include <cJSON.h>

#include "str.h"

typedef struct
{
    str_t   data;
    size_t  capacity;
} curl_data_t;
#define empty_curl_data {empty_str, 0}

extern void curl_data_free(curl_data_t* data);

typedef struct pair_array_s curl_header_t;
#define empty_curl_header empty_pair_array

typedef struct pair_array_s pair_array_t;
struct pair_array_s
{
    str_t*  keys;
    str_t*  vals;
    size_t  count;
};
extern pair_array_t static_empty_pair_array;
#define empty_pair_array {NULL, NULL, 0}

extern void pair_array_free(pair_array_t* array);
extern void pair_array_append_pointers(pair_array_t* array, const char* key, const char* val);
extern void pair_array_append_empty_value(pair_array_t* array, const char* key);
extern str_t pair_array_lookup(pair_array_t* array, str_t key);
extern int pair_array_set(pair_array_t* array, str_t key, str_t val);

typedef struct
{
    enum
    {
        MSG_CONTENT_TYPE_NONE,
        MSG_CONTENT_TYPE_STRING,
        MSG_CONTENT_TYPE_FACE
    } type;
    union
    {
        str_t  string;
        uint   face_id;
    };
} msg_content_t;

typedef struct
{
    msg_content_t*  vals;
    size_t          count;
} msg_content_array_t;
#define empty_msg_content_array {NULL, 0}

#define msg_content_array_empty(array) ((array).count == 0)

extern void msg_content_array_free(msg_content_array_t* array);
extern void msg_content_array_append_string(msg_content_array_t* array, const char* val);
extern void msg_content_array_append_face(msg_content_array_t* array, uint face_id);
extern char* msg_content_array_to_json_object_string(msg_content_array_t* array, const char* key);
extern cJSON* msg_content_array_to_json_value(msg_content_array_t* array);
extern msg_content_array_t msg_content_array_from_json_value(cJSON* src);

#endif

