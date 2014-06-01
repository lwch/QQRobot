#ifndef _MODULE_H_
#define _MODULE_H_

#include "str.h"

typedef int (*module_init_ptr)();
typedef void (*module_exit_ptr)();
typedef int (*module_received_message_ptr)(ullong uin, ullong number, str_t content);
typedef int (*module_received_group_message_ptr)(ullong uin, ullong number, str_t content);

typedef struct
{
    ushort                             version_major;
    ushort                             version_minor;
    ushort                             version_build;
    str_t                              module_name;

    module_init_ptr                    module_init;
    module_exit_ptr                    module_exit;

    module_received_message_ptr        received_message;
    module_received_group_message_ptr  received_group_message;
} module_t;

#define MODULE_DEFAULT_VERSION 1, 0, 0

#endif

