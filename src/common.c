#include <ctype.h>
#include <string.h>

#include "common.h"

char** fetch_response(const char* string, size_t* count)
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

void fetch_cookie(const char* string, cookie_t* cookie)
{
    enum
    {
        none,
        key_start,
        val_start
    } status;
    const char* begin = NULL;
    size_t len;

    status = none;
    cookie->count = 0;
    while (*string)
    {
        switch (status)
        {
        case none:
            if (*string != ' ')
            {
                status = key_start;
                begin = string;
            }
            break;
        case key_start:
            if (*string == '=')
            {
                cookie->keys = realloc(cookie->keys, sizeof(char*) * (cookie->count + 1));
                cookie->vals = realloc(cookie->vals, sizeof(char*) * (cookie->count + 1));
                len = string - begin;
                cookie->keys[cookie->count] = malloc(len + 1);
                memcpy(cookie->keys[cookie->count], begin, len);
                cookie->keys[cookie->count][len] = 0;
                begin = string + 1;
                status = val_start;
            }
            break;
        case val_start:
            if (*string == ';')
            {
                len = string - begin;
                cookie->vals[cookie->count] = malloc(len + 1);
                memcpy(cookie->vals[cookie->count], begin, len);
                cookie->vals[cookie->count][len] = 0;
                ++cookie->count;
                status = none;
            }
            break;
        }
        ++string;
    }
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

size_t urlencode_len(const char* string)
{
    size_t ret = 0;
    while (*string)
    {
        char ch = tolower(*string);
        if ((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || (ch == '=')) ++ret;
        else ret += 3;
        ++string;
    }
    return ret;
}

void urlencode(const char* string, char* out)
{
    char* ptr = out;
    while (*string)
    {
        unsigned char ch = *string;
        if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || (ch == '=')) *ptr = *string;
        else
        {
            unsigned char ch1 = ch >>  4;
            unsigned char ch2 = ch & 0xF;
            *ptr = '%';
            ++ptr;
            *ptr = ch1 >= 10 ? 'A' + ch1 - 10 : '0' + ch1;
            ++ptr;
            *ptr = ch2 >= 10 ? 'A' + ch2 - 10 : '0' + ch1;
        }
        ++ptr;
        ++string;
    }
    *ptr = 0;
}

