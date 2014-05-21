#include <auto_config.h>
#include <auto_module.h>

#include <string.h>

#include "qqrobot.h"

robot_t robot;

module_t core_module = {
    MODULE_DEFAULT_VERSION,
    str("core_module"),
    NULL,
    NULL
};

extern module_t conf_module;

extern int parse_conf_file(str_t path);

static int want_image(int* want)
{
    //curl_data_t data_check = empty_curl_data;
    //curl_header_t header_check = empty_curl_header;
    return 1;
}

static void init()
{
    robot.conf_file = static_empty_str;
    robot.conf = static_empty_pair_array;

    robot.session = static_empty_str;
}

static void run()
{
    size_t i, modules_count;
    //int rc;

    for (modules_count = 0;; ++modules_count)
    {
        if (modules[modules_count] == NULL) break;
        if (modules[modules_count]->module_init) modules[modules_count]->module_init();
    }

    if (!str_empty(robot.conf_file))
    {
        if (!parse_conf_file(robot.conf_file)) return;
    }
    if (!login()) return;

    for (i = 0; i < modules_count; ++i)
    {
        if (modules[i] == &conf_module) continue;
        if (modules[i]->module_exit) modules[i]->module_exit();
    }
    conf_module.module_exit();
}

static void show_usage()
{
}

int login()
{
    int image;
    want_image(&image);
    return 1;
}

int main(int argc, char* argv[])
{
    int i;

    init();
    for (i = 1; i < argc; ++i)
    {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0)
        {
            show_usage();
            break;
        }
        else if (strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--conf") == 0)
        {
            if (i + 1 < argc) robot.conf_file = str_dup(argv[++i]);
            else
            {
                fprintf(stderr, "Error: -c or --conf argument given but no config file specified.\n");
                return 1;
            }
        }
    }
    run();
    str_free(robot.conf_file);
    return 0;
}

