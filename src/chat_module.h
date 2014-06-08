#ifndef _CHAT_MODULE_H_
#define _CHAT_MODULE_H_

#include <auto_config.h>

typedef struct
{
    uint                  disallow_all_friends; // 0支持所有好友，大于等于1为支持的数量
    uint                  disallow_all_groups;  // 0支持所有群，大于等于1为支持的数量
    ullong*               allow_friends; // 允许的好友号列表
    ullong*               allow_groups;  // 允许的群号列表

    ullong                msg_id;
    mongoc_collection_t*  study_collection;
} chat_module_conf_t;

#endif

