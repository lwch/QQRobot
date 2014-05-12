#include <curl/curl.h>
#include <ctype.h>
#include <execinfo.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "../src/common.h"
#include "../src/config.h"
#include "../src/struct.h"

#define BITS_LEN   8
#define VERIFY_LEN 4

static void sig(int idx)
{
    signal(idx, SIG_DFL);

    void* st[20];
    size_t size = backtrace(st, sizeof(st) / sizeof(void*));
    char** strs = (char**)backtrace_symbols(st, size);
    size_t i;

    for (i = 0; i < size; ++i)
    {
        fprintf(stderr, "%lu %s\n", i, strs[i]);
    }
    free(strs);
    exit(1);
}

static void free_char2_pointer(char** ptr, size_t count)
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

static int get_request(const char* url, int ssl, curl_data_t* data, curl_header_t* header)
{
    CURL* curl = curl_easy_init();
    CURLcode res;
    curl_easy_setopt(curl, CURLOPT_URL, url);
    if (ssl)
    {
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0);
    }
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_func);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, data);
    if (header)
    {
        curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, header_func);
        curl_easy_setopt(curl, CURLOPT_HEADERDATA, header);
    }
    res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    if (res != CURLE_OK) return 0;
    return 1;
}

static int get_request_with_cookie(const char* url, int ssl, const char* cookie, curl_data_t* data, curl_header_t* header)
{
    CURL* curl = curl_easy_init();
    CURLcode res;
    curl_easy_setopt(curl, CURLOPT_URL, url);
    if (ssl)
    {
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0);
    }
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_func);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, data);
    if (header)
    {
        curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, header_func);
        curl_easy_setopt(curl, CURLOPT_HEADERDATA, header);
    }
    curl_easy_setopt(curl, CURLOPT_COOKIE, cookie);
    res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    if (res != CURLE_OK) return 0;
    return 1;
}

static void encode_password(const char* password, const char* token, const char* bits, unsigned char out[MD5_DIGEST_LENGTH << 1])
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

int main()
{
    signal(SIGSEGV, sig);
    signal(SIGABRT, sig);

    curl_data_t data_check = {NULL, 0, 0}, data_captcha = {NULL, 0, 0}, data_login = {NULL, 0, 0};
    curl_header_t header_check = {NULL, NULL, 0}, header_captcha = {NULL, NULL, 0}, header_login = {NULL, NULL, 0};
    size_t i, check_value_count, login_value_count;
    char **check_value, **login_value;
    unsigned char md5_pass[MD5_DIGEST_LENGTH << 1] = {0};
    char* cookie;
    char* url = NULL;
    char captcha[VERIFY_LEN + 1] = {0};
    int ret;

    get_request("http://check.ptlogin2.qq.com/check?uin="QQ"&appid=1003903&r=0.14233942252344134", 0, &data_check, &header_check);
    check_value = fetch_data(data_check.ptr, &check_value_count);
    free(data_check.ptr);
    if (strcmp(check_value[0], "0") != 0)
    {
        FILE* fp;
        get_request("https://ssl.captcha.qq.com/getimage?aid=1003903&r=0.577911190026398&uin="QQ, 0, &data_captcha, &header_captcha);

        fp = fopen("captcha.jpeg", "wb");
        fwrite(data_captcha.ptr, data_captcha.len, 1, fp);
        fclose(fp);
        free(data_captcha.ptr);
        fprintf(stdout, "请输入验证码(从captcha.jpeg中)\n");
        scanf("%s", (char*)captcha);
        for (i = 0; i < VERIFY_LEN; ++i) captcha[i] = toupper(captcha[i]);
        captcha[VERIFY_LEN] = 0;
        for (i = 0; i < header_captcha.count; ++i)
        {
            if (strcmp("Set-Cookie", header_captcha.keys[i]) == 0) cookie = header_captcha.vals[i];
        }
    }
    else
    {
        strcpy(captcha, check_value[1]);
        for (i = 0; i < header_check.count; ++i)
        {
            if (strcmp("Set-Cookie", header_check.keys[i]) == 0) cookie = header_check.vals[i];
        }
    }

    encode_password(PASS, captcha, check_value[2], md5_pass);
    url = malloc(sizeof("https://ssl.ptlogin2.qq.com/login?u="QQ"&p=&verifycode=&webqq_type=10&remember_uin=1&login2qq=1&aid=1003903&u1=http%3A%2F%2Fweb2.qq.com%2Floginproxy.html%3Flogin2qq%3D1%26webqq_type%3D10&h=1&ptredirect=0&ptlang=2052&daid=164&from_ui=1&pttype=1&dumy=&fp=loginerroralert&action=6-53-32873&mibao_css=m_webqq&t=4&g=1&js_type=0&js_ver=10077&login_sig=qBpuWCs9dlR9awKKmzdRhV8TZ8MfupdXF6zyHmnGUaEzun0bobwOhMh6m7FQjvWA") + (MD5_DIGEST_LENGTH << 1) + VERIFY_LEN);
    url[0] = 0;
    strcpy(url, "https://ssl.ptlogin2.qq.com/login?u="QQ"&p=");
    strncat(url, (char*)md5_pass, MD5_DIGEST_LENGTH << 1);
    strcat(url, "&verifycode=");
    strcat(url, captcha);
    strcat(url, "&webqq_type=10&remember_uin=1&login2qq=1&aid=1003903&u1=http%3A%2F%2Fweb2.qq.com%2Floginproxy.html%3Flogin2qq%3D1%26webqq_type%3D10&h=1&ptredirect=0&ptlang=2052&daid=164&from_ui=1&pttype=1&dumy=&fp=loginerroralert&action=6-53-32873&mibao_css=m_webqq&t=4&g=1&js_type=0&js_ver=10077&login_sig=qBpuWCs9dlR9awKKmzdRhV8TZ8MfupdXF6zyHmnGUaEzun0bobwOhMh6m7FQjvWA");
    get_request_with_cookie(url, 1, cookie, &data_login, &header_login);
    login_value = fetch_data(data_login.ptr, &login_value_count);
    free(data_login.ptr);
    if (strcmp(login_value[4], "登录成功！") != 0)
    {
        fprintf(stderr, "%s\n", login_value[4]);
        ret = 1;
        goto err;
    }
    fprintf(stdout, "login 成功\n");
    //{"status":"online","ptwebqq":"cb1d8e87afac1646cc2807f987384fb999224dc4e9e3b027f416994d76832657","passwd_sig":"","clientid":"811378975"}

    /*unsigned char pass[MD5_DIGEST_LENGTH << 1] = {0};
    encode_password(PASS, "!HAE", "\\x00\\x00\\x00\\x00\\x1e\\x68\\x0a\\x64", pass);
    printf("%s\n", pass);*/
    ret = 0;
err:
    free_char2_pointer(header_check.keys, header_check.count);
    free_char2_pointer(header_check.vals, header_check.count);
    free_char2_pointer(header_captcha.keys, header_captcha.count);
    free_char2_pointer(header_captcha.vals, header_captcha.count);
    free_char2_pointer(header_login.keys, header_login.count);
    free_char2_pointer(header_login.vals, header_login.count);
    return ret;
}

