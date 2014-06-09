#include <string.h>

#include <cJSON.h>

#include "struct.h"

pair_array_t static_empty_pair_array = empty_pair_array;

inline void curl_data_free(curl_data_t* data)
{
    str_free(data->data);
    data->capacity = 0;
}

void pair_array_free(pair_array_t* array)
{
    str_array_free(array->keys, array->count);
    str_array_free(array->vals, array->count);
    free(array->keys);
    free(array->vals);
    array->keys = array->vals = NULL;
    array->count = 0;
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

int pair_array_set(pair_array_t* array, str_t key, str_t val)
{
    size_t i;
    int ret = 0;
    for (i = 0; i < array->count; ++i)
    {
        if (strncmp(key.ptr, array->keys[i].ptr, key.len) == 0)
        {
            str_free(array->vals[i]);
            array->vals[i] = str_ndup(val.ptr, val.len);
            ret = 1;
            break;
        }
    }
    return ret;
}

void msg_content_array_free(msg_content_array_t* array)
{
    size_t i;
    for (i = 0; i < array->count; ++i)
    {
        switch (array->vals[i].type)
        {
        case MSG_CONTENT_TYPE_STRING:
            str_free(array->vals[i].string);
            break;
        default:
            break;
        }
    }
    free(array->vals);
    array->vals = NULL;
    array->count = 0;
}

void msg_content_array_append_string(msg_content_array_t* array, const char* val)
{
    array->vals = realloc(array->vals, sizeof(*array->vals) * (array->count + 1));
    array->vals[array->count].type = MSG_CONTENT_TYPE_STRING;
    array->vals[array->count].string = str_dup(val);
    ++array->count;
}

void msg_content_array_append_face(msg_content_array_t* array, uint face_id)
{
    array->vals = realloc(array->vals, sizeof(*array->vals) * (array->count + 1));
    array->vals[array->count].type = MSG_CONTENT_TYPE_FACE;
    array->vals[array->count].face_id = face_id;
    ++array->count;
}

char* msg_content_array_to_json_string(msg_content_array_t* array)
{
    size_t i;
    cJSON* cjson_array = cJSON_CreateArray();
    char* ret;

    for (i = 0; i < array->count; ++i)
    {
        switch (array->vals[i].type)
        {
        case MSG_CONTENT_TYPE_STRING:
            cJSON_AddItemToArray(cjson_array, cJSON_CreateString(array->vals[i].string.ptr));
            break;
        case MSG_CONTENT_TYPE_FACE:
            {
                cJSON* cjson_tmp = cJSON_CreateArray();
                cJSON_AddItemToArray(cjson_tmp, cJSON_CreateString("face"));
                cJSON_AddItemToArray(cjson_tmp, cJSON_CreateNumber(array->vals[i].face_id));
                cJSON_AddItemToArray(cjson_array, cjson_tmp);
            }
            break;
        default:
            break;
        }
    }
    ret = cJSON_PrintUnformatted(cjson_array);
    cJSON_Delete(cjson_array);
    return ret;
}

cJSON* msg_content_array_to_json_value(msg_content_array_t* array)
{
    size_t i;
    cJSON* cjson_array = cJSON_CreateArray();

    for (i = 0; i < array->count; ++i)
    {
        switch (array->vals[i].type)
        {
        case MSG_CONTENT_TYPE_STRING:
            cJSON_AddItemToArray(cjson_array, cJSON_CreateString(array->vals[i].string.ptr));
            break;
        case MSG_CONTENT_TYPE_FACE:
            {
                cJSON* cjson_tmp = cJSON_CreateArray();
                cJSON_AddItemToArray(cjson_tmp, cJSON_CreateString("face"));
                cJSON_AddItemToArray(cjson_tmp, cJSON_CreateNumber(array->vals[i].face_id));
                cJSON_AddItemToArray(cjson_array, cjson_tmp);
            }
            break;
        default:
            break;
        }
    }
    return cjson_array;
}

msg_content_array_t msg_content_array_from_json_value(cJSON* src)
{
    msg_content_array_t ret = empty_msg_content_array;
    int count = cJSON_GetArraySize(src);
    int i;

    for (i = 0; i < count; ++i)
    {
        cJSON* item = cJSON_GetArrayItem(src, i);
        switch (item->type)
        {
        case cJSON_String:
            msg_content_array_append_string(&ret, item->valuestring);
            break;
        case cJSON_Array:
            if (strcmp(cJSON_GetArrayItem(item, 0)->valuestring, "face") == 0) msg_content_array_append_face(&ret, cJSON_GetArrayItem(item, 1)->valueint);
            break;
        default:
            break;
        }
    }
    return ret;
}

