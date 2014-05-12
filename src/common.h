#ifndef _COMMON_H_
#define _COMMON_H_

#include <openssl/md5.h>
#include <stdlib.h>

extern char** fetch_data(const char* string, size_t* count);
extern void md5_hex(const unsigned char* string, size_t len, unsigned char out[MD5_DIGEST_LENGTH]);
extern void md5_str(const unsigned char* string, size_t len, unsigned char out[MD5_DIGEST_LENGTH << 1]);

#endif

