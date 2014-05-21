#include <curl/curl.h>

#include <ctype.h>
#include <string.h>

#include <auto_config.h>
#include "common.h"

static size_t write_func(void* ptr, size_t size, size_t nmemb, void* stream)
{
    curl_data_t* data = stream;
    size *= nmemb;
    if (data->capacity - data->len < size)
    {
        data->capacity += size << 1;
        data->ptr = realloc(data->ptr, data->capacity);
    }
    memcpy(data->ptr + data->len, ptr, size);
    data->len += size;
    return size;
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
        if (strcmp(header->keys[i], key) == 0) break;
    }
    if (i == header->count) // 不存在
    {
        header->keys = realloc(header->keys, sizeof(char*) * (header->count + 1));
        header->vals = realloc(header->vals, sizeof(char*) * (header->count + 1));
        header->keys[i] = malloc(strlen(key) + 1);
        strcpy(header->keys[i], key);
        header->vals[i] = NULL;
        ++header->count;
    }
    if (header->vals[i] == NULL)
    {
        header->vals[i] = malloc(strlen(val));
        header->vals[i][0] = 0;
    }
    else
    {
        header->vals[i] = realloc(header->vals[i], strlen(header->vals[i]) + strlen(val));
        offset = 0;
    }
    strncat(header->vals[i], val + offset, strlen(val) - offset - 1);
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
    if (data)
    {
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_func);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, data);
    }
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
    if (data)
    {
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_func);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, data);
    }
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
    if (data)
    {
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_func);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, data);
    }
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
    if (data)
    {
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_func);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, data);
    }
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

void encode_password(const char* password, const char* token, const char* bits, unsigned char out[MD5_DIGEST_LENGTH << 1])
{
    unsigned char md5_pass[MD5_DIGEST_LENGTH] = {0};
    unsigned char md5_src_1[MD5_DIGEST_LENGTH + BITS_LEN] = {0};
    unsigned char md5_src_2[MD5_DIGEST_LENGTH + VERIFY_LEN] = {0};
    unsigned char md5_src[MD5_DIGEST_LENGTH << 1] = {0};
    size_t i;

    md5_hex((unsigned char*)password, strlen(password), md5_pass);
    memcpy(md5_src_1, md5_pass, MD5_DIGEST_LENGTH);
    for (i = 0; i < BITS_LEN; ++i)
    {
        unsigned char ch1 = tolower(bits[(i << 2) + 2]);
        unsigned char ch2 = tolower(bits[(i << 2) + 3]);

        ch1 = (ch1 >= 'a' && ch1 <= 'f') ? ch1 - 'a' + 10 : ch1 - '0';
        ch2 = (ch2 >= 'a' && ch2 <= 'f') ? ch2 - 'a' + 10 : ch2 - '0';
        md5_src_1[MD5_DIGEST_LENGTH + i] = (ch1 << 4) | ch2;
    }
    md5_str(md5_src_1, MD5_DIGEST_LENGTH + BITS_LEN, md5_src);
    memcpy(md5_src_2, md5_src, MD5_DIGEST_LENGTH << 1);
    for (i = 0; i < VERIFY_LEN; ++i)
    {
        md5_src_2[(MD5_DIGEST_LENGTH << 1) + i] = toupper(token[i]);
    }
    md5_str(md5_src_2, (MD5_DIGEST_LENGTH << 1) + VERIFY_LEN, out);
}

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

