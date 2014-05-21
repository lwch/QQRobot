#ifndef _QQROBOT_H_
#define _QQROBOT_H_

#include "str.h"
#include "struct.h"

typedef struct
{
    str_t         conf_file;
    pair_array_t  conf;

    str_t         session;
} robot_t;

extern robot_t robot;

extern int login();

#endif

