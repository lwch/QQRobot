#ifndef _MODULE_H_
#define _MODULE_H_

#include <auto_config.h>

#include "str.h"

typedef int (*module_begin_ptr)();
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

    module_begin_ptr                   module_begin; // 程序启动时，未载入配置文件
    module_init_ptr                    module_init;  // 载入配置文件并初始化后，已连接mongodb
    module_exit_ptr                    module_exit;  // 程序退出前

    module_received_message_ptr        received_message;       // 收到好友消息
    module_received_group_message_ptr  received_group_message; // 收到群消息
} module_t;

#define MODULE_DEFAULT_VERSION 1, 0, 0

#endif

