#include <auto_config.h>
#include <string.h>

#include "common.h"
#include "module.h"
#include "qqrobot.h"
#include "conf_module.h"

#define MAX_LINE_LEN 2048

conf_t static_empty_conf = empty_conf;

static void conf_module_exit();

module_t conf_module = {
    MODULE_DEFAULT_VERSION,
    str("conf_module"),
    NULL,
    NULL,
    conf_module_exit,
    NULL,
    NULL
};

static int is_array(str_t str)
{
    size_t i;
    for (i = 0; i < str.len; ++i)
    {
        if (str.ptr[i] == ',') return 1;
    }
    return 0;
}

inline static int is_bool(str_t str)
{
    if (str.len != sizeof("true") - 1 && str.len != sizeof("false") - 1) return 0;
    return strncmp(str.ptr, "true", sizeof("true") - 1) == 0 || strncmp(str.ptr, "false", sizeof("false") - 1) == 0;
}

static void conf_module_exit()
{
    size_t i;

    for (i = 0; i < robot.conf.count; ++i)
    {
        str_free(robot.conf.keys[i]);
        switch (robot.conf.vals[i].type)
        {
        case CONF_VALUE_TYPE_STRING:
            str_free(robot.conf.vals[i].string);
            break;
        case CONF_VALUE_TYPE_ARRAY:
            str_array_free(robot.conf.vals[i].array.array, robot.conf.vals[i].array.count);
            free(robot.conf.vals[i].array.array);
            break;
        default:
            break;
        }
    }
    free(robot.conf.keys);
    free(robot.conf.vals);
    robot.conf.keys = NULL;
    robot.conf.vals = NULL;
    robot.conf.count = 0;
}

int parse_conf_file(str_t path)
{
    char line[MAX_LINE_LEN];
    char *ptr;
    char key[MAX_LINE_LEN], val[MAX_LINE_LEN];
    size_t i;
    FILE* fp = fopen(path.ptr, "r");

    if (fp == NULL)
    {
        // TODO: log
        return 0;
    }

    line[MAX_LINE_LEN - 1] = 0;
    while (!feof(fp))
    {
        str_t trim = static_empty_str;

        ptr = fgets(line, sizeof(line) - 1, fp);
        ptr = line;
        memset(key, 0, MAX_LINE_LEN);
        memset(val, 0, MAX_LINE_LEN);
        while (*ptr)
        {
            if (*ptr != ' ') break;
            ++ptr;
        }

        if (*ptr == '#' || *ptr == '\n') continue;

        i = 0;
        while (*ptr)
        {
            if (*ptr == '=' || *ptr == ' ' || *ptr == '#' || *ptr == '\n') break;
            key[i++] = *ptr;
            ++ptr;
        }

        if (*ptr == '\n')
        {
            conf_append_empty_value(&robot.conf, key);
            continue;
        }

        while (*ptr)
        {
            if (*ptr != '=' && *ptr != ' ') break;
            ++ptr;
        }

        i = 0;
        while (*ptr)
        {
            if (*ptr == '\n' || *ptr == '#') break;
            val[i++] = *ptr;
            ++ptr;
        }
        if (str_trim(val, i, &trim) > 0)
        {
            if (is_array(trim))
            {
                str_t* array = NULL;
                size_t count = str_split(trim.ptr, ",", &array);
                size_t i;

                for (i = 0; i < count; ++i)
                {
                    str_t old = array[i];
                    str_trim(array[i].ptr, array[i].len, &array[i]);
                    str_free(old);
                }
                conf_append_array_ref(&robot.conf, key, array, count);
            }
            else if (is_bool(trim)) conf_append_bool(&robot.conf, key, strncmp(trim.ptr, "true", sizeof("true") - 1) == 0);
            else conf_append_strs(&robot.conf, key, trim.ptr);
            str_free(trim);
        }
        else conf_append_empty_value(&robot.conf, key);
    }
    fclose(fp);
    return 1;
}

conf_val_t conf_lookup(conf_t* conf, str_t key)
{
    conf_val_t ret = empty_conf_value;
    size_t i;

    for (i = 0; i < conf->count; ++i)
    {
        if (strncmp(key.ptr, conf->keys[i].ptr, key.len) == 0)
        {
            ret = conf->vals[i];
            break;
        }
    }
    return ret;
}

void conf_append_bool(conf_t* conf, const char* key, uchar val)
{
    conf->keys = realloc(conf->keys, sizeof(*conf->keys) * (conf->count + 1));
    conf->vals = realloc(conf->vals, sizeof(*conf->vals) * (conf->count + 1));
    conf->keys[conf->count] = str_dup(key);
    conf->vals[conf->count].type = CONF_VALUE_TYPE_BOOL;
    conf->vals[conf->count].bval = val;
    ++conf->count;
}

void conf_append_strs(conf_t* conf, const char* key, const char* val)
{
    conf->keys = realloc(conf->keys, sizeof(*conf->keys) * (conf->count + 1));
    conf->vals = realloc(conf->vals, sizeof(*conf->vals) * (conf->count + 1));
    conf->keys[conf->count] = str_dup(key);
    conf->vals[conf->count].type = CONF_VALUE_TYPE_STRING;
    conf->vals[conf->count].string = str_dup(val);
    ++conf->count;
}

void conf_append_array_ref(conf_t* conf, const char* key, str_t* array, size_t count)
{
    conf->keys = realloc(conf->keys, sizeof(*conf->keys) * (conf->count + 1));
    conf->vals = realloc(conf->vals, sizeof(*conf->vals) * (conf->count + 1));
    conf->keys[conf->count] = str_dup(key);
    conf->vals[conf->count].type = CONF_VALUE_TYPE_ARRAY;
    conf->vals[conf->count].array.array = array;
    conf->vals[conf->count].array.count = count;
    ++conf->count;
}

void conf_append_empty_value(conf_t* conf, const char* key)
{
    conf->keys = realloc(conf->keys, sizeof(*conf->keys) * (conf->count + 1));
    conf->vals = realloc(conf->vals, sizeof(*conf->vals) * (conf->count + 1));
    conf->keys[conf->count] = str_dup(key);
    conf->vals[conf->count].type = CONF_VALUE_TYPE_NONE;
    ++conf->count;
}

