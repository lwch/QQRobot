#include <auto_config.h>

#include "qqrobot.h"

robot_t robot;

static void run()
{
}

static void show_usage()
{
}

int main(int argc, char* argv[])
{
    str_t conf_file;
    int i;

    for (i = 1; i < argc; ++i)
    {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0)
        {
            show_usage();
            break;
        }
        else if (strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--conf") == 0)
        {
            if (i + 1 < argc) conf_file = str_dup(argv[++i]);
            else
            {
                fprintf(stderr, "Error: -c or --conf argument given but no config file specified.\n");
                return 1;
            }
        }
    }
    run();
    str_free(conf_file);
    return 0;
}

