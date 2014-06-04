#ifndef _QQROBOT_H_
#define _QQROBOT_H_

#include "module.h"
#include "str.h"
#include "struct.h"

#include <mongoc.h>

typedef struct
{
    str_t                               conf_file;
    pair_array_t                        conf;

    char                                verify_code[VERIFY_LEN + 1];
    uchar                               bits[BITS_LEN];
    str_t                               ptwebqq;  // reference from cookie
    pair_array_t                        cookie;
    str_t                               session;
    str_t                               vfwebqq;

    mongoc_client_t*                    mongoc_client;
    mongoc_database_t*                  mongoc_database;

    int                                 run;

    module_received_message_ptr*        received_message_funcs;
    size_t                              received_message_funcs_count;
    module_received_group_message_ptr*  received_group_message_funcs;
    size_t                              received_group_message_funcs_count;
} robot_t;

extern robot_t robot;

extern int login();

#endif

