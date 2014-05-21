#ifndef _COMMON_H_
#define _COMMON_H_

#include <openssl/md5.h>
#include <stdlib.h>

#include "struct.h"

extern void free_char2_pointer(char** ptr, size_t count);

extern int get_request(const char* url, int ssl, curl_data_t* data, curl_header_t* header);
extern int get_request_with_cookie(const char* url, int ssl, const char* cookie, curl_data_t* data, curl_header_t* header);
extern int post_request(const char* url, int ssl, const char* post_data, curl_data_t* data, curl_header_t* header);
extern int post_request_with_cookie(const char* url, int ssl, const char* post_data, const char* cookie, curl_data_t* data, curl_header_t* header);

extern void encode_password(const char* password, const char* token, const char* bits, unsigned char out[MD5_DIGEST_LENGTH << 1]);
extern char** fetch_response(const char* string, size_t* count);
extern void fetch_cookie(const char* string, cookie_t* cookie);
extern void md5_hex(const unsigned char* string, size_t len, unsigned char out[MD5_DIGEST_LENGTH]);
extern void md5_str(const unsigned char* string, size_t len, unsigned char out[MD5_DIGEST_LENGTH << 1]);
extern size_t urlencode_len(const char* string);
extern void urlencode(const char* string, char* out);

#endif

