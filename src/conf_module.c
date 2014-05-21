#include <auto_config.h>
#include <string.h>

#include "module.h"
#include "qqrobot.h"

#define MAX_LINE_LEN 1024

static void conf_module_exit();

module_t conf_module = {
    MODULE_DEFAULT_VERSION,
    str("conf_module"),
    NULL,
    conf_module_exit
};

inline static void conf_module_exit()
{
    pair_array_free(&robot.conf);
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

    line[MAX_LINE_LEN] = 0;
    while (!feof(fp))
    {
        fgets(line, sizeof(line) - 1, fp);
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
            pair_array_append_empty_value(&robot.conf, key);
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
            if (*ptr == '\n' || *ptr == ' ' || *ptr == '#') break;
            val[i++] = *ptr;
            ++ptr;
        }
        pair_array_append_pointers(&robot.conf, key, val);
    }
    fclose(fp);
    return 1;
}

