#include <string.h>

#include "struct.h"

pair_array_t static_empty_pair_array = empty_pair_array;

inline void curl_data_free(curl_data_t* data)
{
    str_free(data->data);
}

void pair_array_free(pair_array_t* array)
{
    str_array_free(array->keys, array->count);
    str_array_free(array->vals, array->count);
    free(array->keys);
    free(array->vals);
}

void pair_array_append_pointers(pair_array_t* array, const char* key, const char* val)
{
    array->keys = realloc(array->keys, sizeof(*array->keys) * (array->count + 1));
    array->vals = realloc(array->vals, sizeof(*array->vals) * (array->count + 1));
    array->keys[array->count] = str_dup(key);
    array->vals[array->count] = str_dup(val);
    ++array->count;
}

void pair_array_append_empty_value(pair_array_t* array, const char* key)
{
    array->keys = realloc(array->keys, sizeof(*array->keys) * (array->count + 1));
    array->vals = realloc(array->vals, sizeof(*array->vals) * (array->count + 1));
    array->keys[array->count] = str_dup(key);
    array->vals[array->count] = static_empty_str;
    ++array->count;
}

str_t pair_array_lookup(pair_array_t* array, str_t key)
{
    size_t i;
    str_t ret = empty_str;
    for (i = 0; i < array->count; ++i)
    {
        if (strncmp(key.ptr, array->keys[i].ptr, key.len) == 0)
        {
            ret = array->vals[i];
            break;
        }
    }
    return ret;
}

