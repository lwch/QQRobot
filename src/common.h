#ifndef _COMMON_H_
#define _COMMON_H_

#include <openssl/md5.h>
#include <stdlib.h>

#include "struct.h"

extern char** fetch_response(const char* string, size_t* count);
extern void fetch_cookie(const char* string, cookie_t* cookie);
extern void md5_hex(const unsigned char* string, size_t len, unsigned char out[MD5_DIGEST_LENGTH]);
extern void md5_str(const unsigned char* string, size_t len, unsigned char out[MD5_DIGEST_LENGTH << 1]);
extern size_t urlencode_len(const char* string);
extern void urlencode(const char* string, char* out);

#endif

