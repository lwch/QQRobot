#include <string.h>

#include "common.h"

char** fetch_data(const char* string, size_t* count)
{
    enum
    {
        none,
        start
    } status;
    const char* begin = NULL;
    size_t len;
    char** ret = NULL;

    status = none;
    *count = 0;
    while (*string)
    {
        if (*string == '\'')
        {
            if (status == none)
            {
                begin = string + 1;
                status = start;
            }
            else
            {
                len = string - begin;
                ret = realloc(ret, sizeof(char*) * (*count + 1));
                ret[*count] = malloc(len + 1);
                memcpy(ret[*count], begin, len);
                ret[*count][len] = 0;
                ++*count;
                status = none;
                begin = NULL;
            }
        }
        ++string;
    }
    return ret;
}

void md5_hex(const unsigned char* string, size_t len, unsigned char out[MD5_DIGEST_LENGTH])
{
    MD5_CTX ctx;
    MD5_Init(&ctx);
    MD5_Update(&ctx, string, len);
    MD5_Final(out, &ctx);
}

void md5_str(const unsigned char* string, size_t len, unsigned char out[MD5_DIGEST_LENGTH << 1])
{
    MD5_CTX ctx;
    int i;

    MD5_Init(&ctx);
    MD5_Update(&ctx, string, len);
    MD5_Final(out, &ctx);
    for (i = MD5_DIGEST_LENGTH - 1; i >= 0; --i)
    {
        unsigned char ch = out[i];
        unsigned char ch1 = ch / 16;
        unsigned char ch2 = ch % 16;
        ch1 = (ch1 >= 10) ? ('A' + ch1 - 10) : ('0' + ch1);
        ch2 = (ch2 >= 10) ? ('A' + ch2 - 10) : ('0' + ch2);
        out[(i << 1) + 0] = ch1;
        out[(i << 1) + 1] = ch2;
    }
}

