#ifndef _QQROBOT_H_
#define _QQROBOT_H_

#include "str.h"

typedef struct
{
    str_t  conf_file;

    str_t  session;
} robot_t;

extern robot_t robot;

#endif

