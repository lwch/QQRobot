#ifndef _COMMON_H_
#define _COMMON_H_

#include <openssl/md5.h>
#include <stdlib.h>

#include "struct.h"

extern void free_char2_pointer(char** ptr, size_t count);

extern int get_request(const char* url, int ssl, const char* pem_path, curl_data_t* data, curl_header_t* header);
extern int get_request_with_cookie(const char* url, int ssl, const char* pem_path, const char* cookie, curl_data_t* data, curl_header_t* header);
extern int post_request(const char* url, int ssl, const char* pem_path, const char* post_data, curl_data_t* data, curl_header_t* header);
extern int post_request_with_cookie(const char* url, int ssl, const char* pem_path, const char* post_data, const char* cookie, curl_data_t* data, curl_header_t* header);

extern str_t* fetch_response(const str_t string, size_t* count);
extern void fetch_cookie(const str_t string, pair_array_t* cookie);
extern void merge_cookie(pair_array_t* dst, const pair_array_t* src);
extern str_t cookie_to_str(pair_array_t* cookie);
extern void md5_hex(const unsigned char* string, size_t len, unsigned char out[MD5_DIGEST_LENGTH]);
extern void md5_str(const unsigned char* string, size_t len, unsigned char out[MD5_DIGEST_LENGTH << 1]);
extern void urlencode(const str_t string, str_t* out);

#endif

