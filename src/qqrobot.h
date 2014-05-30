#ifndef _QQROBOT_H_
#define _QQROBOT_H_

#include "str.h"
#include "struct.h"

typedef struct
{
    str_t         conf_file;
    pair_array_t  conf;

    char          verify_code[VERIFY_LEN + 1];
    uchar         bits[BITS_LEN];
    str_t         ptwebqq;
    pair_array_t  cookie;
    str_t         session;
} robot_t;

extern robot_t robot;

extern int login();

#endif

