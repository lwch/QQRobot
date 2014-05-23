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

extern void bits_from_str(str_t str, uchar bits[BITS_LEN]);
extern void encode_password(const str_t password, const char verify_code[VERIFY_LEN], const uchar bits[BITS_LEN], unsigned char out[MD5_DIGEST_LENGTH << 1]);
extern str_t* fetch_response(const str_t string, size_t* count);
extern void fetch_cookie(const str_t string, pair_array_t* cookie);
extern void merge_cookie(pair_array_t* dst, const pair_array_t* src);
extern void md5_hex(const unsigned char* string, size_t len, unsigned char out[MD5_DIGEST_LENGTH]);
extern void md5_str(const unsigned char* string, size_t len, unsigned char out[MD5_DIGEST_LENGTH << 1]);
extern size_t urlencode_len(const str_t string);
extern void urlencode(const str_t string, char* out);

#endif

