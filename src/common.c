#include <curl/curl.h>

#include <ctype.h>
#include <string.h>

#include <auto_config.h>
#include "common.h"

static size_t write_func(void* ptr, size_t size, size_t nmemb, void* stream)
{
    curl_data_t* data = stream;
    size *= nmemb;
    if (data->capacity - data->data.len < size)
    {
        data->capacity += size << 1;
        data->data.ptr = realloc(data->data.ptr, data->capacity);
    }
    memcpy(data->data.ptr + data->data.len, ptr, size);
    data->data.len += size;
    return size;
}

inline static size_t dummy_write_func(void* ptr, size_t size, size_t nmemb, void* stream)
{
    return size * nmemb;
}

static size_t header_func(void* ptr, size_t size, size_t nmemb, void* stream)
{
    curl_header_t* header = stream;
    size_t i;
    char* key = strtok(ptr, ": ");
    char* val = strtok(NULL, "\n");
    size_t offset = 1;

    size *= nmemb;
    if (*key == '\r' || strncmp(key, "HTTP/", sizeof("HTTP/") - 1) == 0) return size;

    for (i = 0; i < header->count; ++i)
    {
        if (strcmp(header->keys[i].ptr, key) == 0) break;
    }
    if (i == header->count) // 不存在
    {
        header->keys = realloc(header->keys, sizeof(str_t) * (header->count + 1));
        header->vals = realloc(header->vals, sizeof(str_t) * (header->count + 1));

        header->keys[i] = str_dup(key);
        header->vals[i] = static_empty_str;
        ++header->count;
    }
    if (!str_empty(header->vals[i])) offset = 0;
    str_ncat(&header->vals[i], val + offset, strlen(val) - offset - 1);
    return size;
}

void free_char2_pointer(char** ptr, size_t count)
{
    if (ptr)
    {
        size_t i;
        for (i = 0; i < count; ++i)
        {
            if (ptr[i]) free(ptr[i]);
        }
        free(ptr);
    }
}

int get_request(const char* url, int ssl, curl_data_t* data, curl_header_t* header)
{
    CURL* curl = curl_easy_init();
    CURLcode res;
    curl_easy_setopt(curl, CURLOPT_URL, url);
    if (ssl)
    {
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0);
    }
    if (data) curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_func);
    else curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, dummy_write_func);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, data);
    if (header)
    {
        curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, header_func);
        curl_easy_setopt(curl, CURLOPT_HEADERDATA, header);
    }
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1);
    res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    if (res != CURLE_OK)
    {
        fprintf(stderr, "curl error: %u\n", res);
        return 0;
    }
    return 1;
}

int get_request_with_cookie(const char* url, int ssl, const char* cookie, curl_data_t* data, curl_header_t* header)
{
    CURL* curl = curl_easy_init();
    CURLcode res;
    curl_easy_setopt(curl, CURLOPT_URL, url);
    if (ssl)
    {
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0);
    }
    if (data) curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_func);
    else curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, dummy_write_func);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, data);
    if (header)
    {
        curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, header_func);
        curl_easy_setopt(curl, CURLOPT_HEADERDATA, header);
    }
    curl_easy_setopt(curl, CURLOPT_COOKIE, cookie);
    res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    if (res != CURLE_OK)
    {
        fprintf(stderr, "curl error: %u\n", res);
        return 0;
    }
    return 1;
}

int post_request(const char* url, int ssl, const char* post_data, curl_data_t* data, curl_header_t* header)
{
    CURL* curl = curl_easy_init();
    CURLcode res;
    curl_easy_setopt(curl, CURLOPT_URL, url);
    if (ssl)
    {
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0);
    }
    if (data) curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_func);
    else curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, dummy_write_func);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, data);
    if (header)
    {
        curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, header_func);
        curl_easy_setopt(curl, CURLOPT_HEADERDATA, header);
    }
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);
    res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    if (res != CURLE_OK)
    {
        fprintf(stderr, "curl error: %u\n", res);
        return 0;
    }
    return 1;
}

int post_request_with_cookie(const char* url, int ssl, const char* post_data, const char* cookie, curl_data_t* data, curl_header_t* header)
{
    CURL* curl = curl_easy_init();
    CURLcode res;
    curl_easy_setopt(curl, CURLOPT_URL, url);
    if (ssl)
    {
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0);
    }
    if (data) curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_func);
    else curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, dummy_write_func);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, data);
    if (header)
    {
        curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, header_func);
        curl_easy_setopt(curl, CURLOPT_HEADERDATA, header);
    }
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);
    curl_easy_setopt(curl, CURLOPT_COOKIE, cookie);
    curl_easy_setopt(curl, CURLOPT_REFERER, "http://d.web2.qq.com/proxy.html?v=20110331002&callback=1&id=2");
    res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    if (res != CURLE_OK)
    {
        fprintf(stderr, "curl error: %u\n", res);
        return 0;
    }
    return 1;
}

str_t* fetch_response(const str_t string, size_t* count)
{
    enum
    {
        none,
        start
    } status;
    size_t i, begin, len;
    str_t* ret = NULL;

    status = none;
    *count = 0;
    for (i = 0; i < string.len; ++i)
    {
        if (string.ptr[i] == '\'')
        {
            if (status == none)
            {
                begin = i + 1;
                status = start;
            }
            else
            {
                len = i - begin;
                ret = realloc(ret, sizeof(str_t) * (*count + 1));
                ret[*count] = str_ndup(&string.ptr[begin], len);
                ++*count;
                status = none;
            }
        }
    }
    return ret;
}

void fetch_cookie(const str_t string, pair_array_t* cookie)
{
    enum
    {
        none,
        key_start,
        val_start
    } status;
    size_t i, begin, len;

    status = none;
    cookie->count = 0;
    for (i = 0; i < string.len; ++i)
    {
        switch (status)
        {
        case none:
            if (string.ptr[i] != ' ')
            {
                status = key_start;
                begin = i;
            }
            break;
        case key_start:
            if (string.ptr[i] == '=')
            {
                cookie->keys = realloc(cookie->keys, sizeof(*cookie->keys) * (cookie->count + 1));
                cookie->vals = realloc(cookie->vals, sizeof(*cookie->vals) * (cookie->count + 1));
                len = i - begin;
                cookie->keys[cookie->count] = str_ndup(&string.ptr[begin], len);
                begin = i + 1;
                status = val_start;
            }
            break;
        case val_start:
            if (string.ptr[i] == ';')
            {
                len = i - begin;
                cookie->vals[cookie->count] = str_ndup(&string.ptr[begin], len);
                ++cookie->count;
                status = none;
            }
            break;
        }
    }
}

void merge_cookie(pair_array_t* dst, const pair_array_t* src)
{
    size_t i, j;
    int find;
    for (i = 0; i < src->count; ++i)
    {
        if (src->vals[i].len == 0) continue;
        find = 0;
        for (j = 0; j < dst->count; ++j)
        {
            if (strcmp(dst->keys[j].ptr, src->keys[i].ptr) == 0)
            {
                find = 1;
                str_free(dst->vals[j]);
                str_cpy(&dst->vals[j], src->vals[i]);
                break;
            }
        }
        if (!find)
        {
            dst->keys = realloc(dst->keys, sizeof(*dst->keys) * (dst->count + 1));
            dst->vals = realloc(dst->vals, sizeof(*dst->vals) * (dst->count + 1));
            dst->keys[dst->count] = str_ndup(src->keys[i].ptr, src->keys[i].len);
            dst->vals[dst->count] = str_ndup(src->vals[i].ptr, src->vals[i].len);
            ++dst->count;
        }
    }
}

str_t cookie_to_str(pair_array_t* cookie)
{
    str_t ret;
    size_t i, len;
    char* ptr;
    for (i = 0, len = 0; i < cookie->count; ++i)
    {
        len += cookie->keys[i].len;
        len += sizeof("=") - 1;
        len += cookie->vals[i].len;
        len += sizeof("; ") - 1;
    }
    ret.ptr = ptr = malloc(len);
    for (i = 0; i < cookie->count; ++i)
    {
        memcpy(ptr, cookie->keys[i].ptr, cookie->keys[i].len);
        ptr += cookie->keys[i].len;
        *ptr++ = '=';
        memcpy(ptr, cookie->vals[i].ptr, cookie->vals[i].len);
        ptr += cookie->vals[i].len;
        *ptr++ = ';';
        *ptr++ = ' ';
    }
    ret.ptr[len] = 0;
    ret.len = len;
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

static size_t urlencode_len(const char* string, size_t len)
{
    size_t i, ret = 0;
    for (i = 0; i < len; ++i)
    {
        char ch = tolower(string[i]);
        if ((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || (ch == '=') || (ch == '_') || (ch == '&')) ++ret;
        else ret += 3;
    }
    return ret;
}

void urlencode(const str_t string, str_t* out)
{
    size_t i;
    out->len = urlencode_len(string.ptr, string.len);
    out->ptr = malloc(out->len + 1);
    char* ptr = out->ptr;
    for (i = 0; i < string.len; ++i)
    {
        uchar ch = string.ptr[i];
        if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || (ch == '=') || (ch == '_') || (ch == '&')) *ptr = ch;
        else
        {
            uchar ch1 = ch >>  4;
            uchar ch2 = ch & 0xF;
            *ptr++ = '%';
            *ptr++ = ch1 >= 10 ? 'A' + ch1 - 10 : '0' + ch1;
            *ptr = ch2 >= 10 ? 'A' + ch2 - 10 : '0' + ch2;
        }
        ++ptr;
    }
    *ptr = 0;
}

