#include <auto_config.h>
#include <auto_module.h>

#include <execinfo.h>
#include <signal.h>
#include <string.h>

#include <cJSON.h>

#include "common.h"
#include "qqrobot.h"

robot_t robot;

module_t core_module = {
    MODULE_DEFAULT_VERSION,
    str("core_module"),
    NULL,
    NULL
};

extern module_t conf_module;

extern int parse_conf_file(str_t path);

static void crash_sig(int signum)
{
    void* array[10];
    size_t size;
    char** strings;
    size_t i;

    signal(signum, SIG_DFL);

    size = backtrace(array, sizeof(array) / sizeof(void*));
    strings = (char**)backtrace_symbols(array, size);

    for (i = 0; i < size; ++i)
    {
        fprintf(stderr, "%s\n", strings[i]);
    }

    free(strings);
    exit(1);
}

static void dummy_sig(int i)
{
}

static int want_image(int* want)
{
    curl_data_t data_check = empty_curl_data;
    curl_header_t header_check = empty_curl_header;
    pair_array_t cookie = empty_pair_array;
    str_t number = pair_array_lookup(&robot.conf, str_from("QQ"));
    char* url = malloc(sizeof("https://ssl.ptlogin2.qq.com/check?uin=&appid=1003903&r=0.14233942252344134") + number.len);
    str_t* check_response = NULL;
    int rc = 1;
    size_t check_response_count = 0;
    size_t i;

    url[0] = 0;
    strcpy(url, "https://ssl.ptlogin2.qq.com/check?uin=");
    strncat(url, number.ptr, number.len);
    strcat(url, "&appid=1003903&r=0.14233942252344134");
    rc = get_request(url, 1, &data_check, &header_check);
    if (!rc)
    {
        fprintf(stderr, "Call check error!!!!\n");
        goto end;
    }

    for (i = 0; i < header_check.count; ++i)
    {
        if (strcmp("Set-Cookie", header_check.keys[i].ptr) == 0)
        {
            fetch_cookie(header_check.vals[i], &cookie);
            merge_cookie(&robot.cookie, &cookie);
            pair_array_free(&cookie);
        }
    }

    check_response = fetch_response(data_check.data, &check_response_count);
    if (strcmp(check_response[0].ptr, "0") == 0) *want = 0;
    else if (strcmp(check_response[0].ptr, "2") == 0)
    {
        fprintf(stderr, "Invalid QQ Number!!!!\n");
        goto end;
    }
    else *want = 1;
    memcpy(robot.verify_code, check_response[1].ptr, VERIFY_LEN);
    bits_from_str(check_response[2], robot.bits);

end:
    curl_data_free(&data_check);
    pair_array_free(&header_check);
    free(url);
    str_array_free(check_response, check_response_count);
    return rc;
}

static int download_image(const str_t captcha_path)
{
    curl_data_t data_getimage = empty_curl_data;
    curl_header_t header_getimage = empty_curl_header;
    pair_array_t cookie = empty_pair_array;
    str_t number = pair_array_lookup(&robot.conf, str_from("QQ"));
    char* url = malloc(sizeof("https://ssl.captcha.qq.com/getimage?aid=1003903&r=0.577911190026398&uin=") + number.len);
    int rc = 1;
    size_t i;

    FILE* fp;

    url[0] = 0;
    strcpy(url, "https://ssl.captcha.qq.com/getimage?aid=1003903&r=0.577911190026398&uin=");
    strncat(url, number.ptr, number.len);
    rc = get_request(url, 1, &data_getimage, &header_getimage);
    if (!rc)
    {
        fprintf(stderr, "Call getimage error!!!!\n");
        goto end;
    }

    for (i = 0; i < header_getimage.count; ++i)
    {
        if (strcmp("Set-Cookie", header_getimage.keys[i].ptr) == 0)
        {
            fetch_cookie(header_getimage.vals[i], &cookie);
            merge_cookie(&robot.cookie, &cookie);
            pair_array_free(&cookie);
        }
    }

    fp = fopen(captcha_path.ptr, "wb");
    if (fp == NULL)
    {
        rc = 0;
        fprintf(stderr, "Can not open captcha file!!!!\n");
        goto end;
    }
    fwrite(data_getimage.data.ptr, sizeof(char), data_getimage.data.len, fp);
    fclose(fp);

end:
    curl_data_free(&data_getimage);
    pair_array_free(&header_getimage);
    free(url);
    return rc;
}

static int login_proxy(const char* url)
{
    curl_header_t header_proxy = empty_curl_header;
    pair_array_t cookie;
    int rc = 1;
    size_t i;

    rc = get_request(url, 0, NULL, &header_proxy);
    if (!rc)
    {
        fprintf(stderr, "Call proxy error!!!!\n");
        goto end;
    }

    for (i = 0; i < header_proxy.count; ++i)
    {
        if (strcmp("Set-Cookie", header_proxy.keys[i].ptr) == 0)
        {
            fetch_cookie(header_proxy.vals[i], &cookie);
            merge_cookie(&robot.cookie, &cookie);
            pair_array_free(&cookie);
        }
    }
end:
    pair_array_free(&header_proxy);
    return rc;
}

static int login_step1(const unsigned char password[MD5_DIGEST_LENGTH << 1])
{
    curl_data_t data_login = empty_curl_data;
    curl_header_t header_login = empty_curl_header;
    str_t number = pair_array_lookup(&robot.conf, str_from("QQ"));
    pair_array_t cookie;
    str_t cookie_str;
    char* url = malloc(sizeof("https://ssl.ptlogin2.qq.com/login?u=&p=&verifycode=&webqq_type=10&remember_uin=1&login2qq=1&aid=1003903&u1=http%3A%2F%2Fweb2.qq.com%2Floginproxy.html%3Flogin2qq%3D1%26webqq_type%3D10&h=1&ptredirect=0&ptlang=2052&daid=164&from_ui=1&pttype=1&dumy=&fp=loginerroralert&action=6-53-32873&mibao_css=m_webqq&t=4&g=1&js_type=0&js_ver=10077&login_sig=qBpuWCs9dlR9awKKmzdRhV8TZ8MfupdXF6zyHmnGUaEzun0bobwOhMh6m7FQjvWA") + sizeof(password) + VERIFY_LEN + number.len);
    str_t* login_response = NULL;
    int rc = 1;
    size_t login_response_count = 0;
    size_t i;

    url[0] = 0;
    strcpy(url, "https://ssl.ptlogin2.qq.com/login?u=");
    strncat(url, number.ptr, number.len);
    strcat(url, "&p=");
    strncat(url, (char*)password, sizeof(password));
    strcat(url, "verifycode=");
    strncat(url, robot.verify_code, VERIFY_LEN);
    strcat(url, "&webqq_type=10&remember_uin=1&login2qq=1&aid=1003903&u1=http%3A%2F%2Fweb2.qq.com%2Floginproxy.html%3Flogin2qq%3D1%26webqq_type%3D10&h=1&ptredirect=0&ptlang=2052&daid=164&from_ui=1&pttype=1&dumy=&fp=loginerroralert&action=6-53-32873&mibao_css=m_webqq&t=4&g=1&js_type=0&js_ver=10077&login_sig=qBpuWCs9dlR9awKKmzdRhV8TZ8MfupdXF6zyHmnGUaEzun0bobwOhMh6m7FQjvWA");

    cookie_str = cookie_to_str(&robot.cookie);
    rc = get_request_with_cookie(url, 1, cookie_str.ptr, &data_login, &header_login);
    if (!rc)
    {
        fprintf(stderr, "Call login error!!!!\n");
        goto end;
    }

    for (i = 0; i < header_login.count; ++i)
    {
        if (strcmp("Set-Cookie", header_login.keys[i].ptr) == 0)
        {
            fetch_cookie(header_login.vals[i], &cookie);
            merge_cookie(&robot.cookie, &cookie);
            pair_array_free(&cookie);
        }
    }
    robot.ptwebqq = pair_array_lookup(&robot.cookie, str_from("ptwebqq"));

    login_response = fetch_response(data_login.data, &login_response_count);
    if (strcmp(login_response[4].ptr, "登录成功！") != 0)
    {
        rc = 0;
        goto end;
    }

    rc = login_proxy(login_response[2].ptr);
end:
    curl_data_free(&data_login);
    pair_array_free(&header_login);
    str_free(cookie_str);
    free(url);
    str_array_free(login_response, login_response_count);
    return rc;
}

static int login_step2()
{
    curl_data_t data_login2;
    curl_header_t header_login2;
    cJSON* cjson_login = cJSON_CreateObject();
    str_t post_data = empty_str, tmp = empty_str;
    str_t cookie_str;
    str_t status = pair_array_lookup(&robot.conf, str_from("STATUS"));
    int rc = 1;

    cJSON_AddStringToObject(cjson_login, "status", status.ptr);
    cJSON_AddStringToObject(cjson_login, "ptwebqq", robot.ptwebqq.ptr);
    cJSON_AddStringToObject(cjson_login, "passwd_sig", "");
    //cJSON_AddStringToObject(cjson_login, "clientid", CLIENTID);
    //cJSON_AddNullToObject(cjson_login, "psessionid");
    post_data.ptr = cJSON_PrintUnformatted(cjson_login);
    post_data.len = strlen(post_data.ptr);
    str_cpy(&tmp, str_from("r="));
    str_ncat(&tmp, post_data.ptr, post_data.len);
    str_cat(&tmp, "&clientid="CLIENTID"&psessionid=null");
    str_free(post_data);
    urlencode(tmp, &post_data);

    cookie_str = cookie_to_str(&robot.cookie);
    rc = post_request_with_cookie("https://d.web2.qq.com/channel/login2", 1, post_data.ptr, cookie_str.ptr, &data_login2, &header_login2);
    if (!rc)
    {
        fprintf(stderr, "Call login2 error!!!!\n");
        goto end;
    }
end:
    curl_data_free(&data_login2);
    pair_array_free(&header_login2);
    cJSON_Delete(cjson_login);
    str_free(post_data);
    str_free(tmp);
    str_free(cookie_str);
    return rc;
}

static void init()
{
    robot.conf_file = static_empty_str;
    robot.conf = static_empty_pair_array;

    memset(robot.verify_code, 0, VERIFY_LEN);
    memset(robot.bits, 0, BITS_LEN);
    robot.cookie = static_empty_pair_array;
    robot.session = static_empty_str;
}

static void run()
{
    size_t i, modules_count;
    //int rc;

    for (modules_count = 0;; ++modules_count)
    {
        if (modules[modules_count] == NULL) break;
        if (modules[modules_count]->module_init) modules[modules_count]->module_init();
    }

    if (!str_empty(robot.conf_file))
    {
        if (!parse_conf_file(robot.conf_file)) return;
    }
    else
    {
        fprintf(stderr, "Please input configure file!!!!\n");
        return;
    }
    if (str_empty(pair_array_lookup(&robot.conf, str_from("QQ"))) || str_empty(pair_array_lookup(&robot.conf, str_from("PASSWORD"))))
    {
        fprintf(stderr, "Please input configure file with QQ and PASSWORD!!!!\n");
        return;
    }
    if (!login()) return;

    for (i = 0; i < modules_count; ++i)
    {
        if (modules[i] == &conf_module) continue;
        if (modules[i]->module_exit) modules[i]->module_exit();
    }
    conf_module.module_exit();
}

static void show_usage()
{
}

int login()
{
    int image;
    int rc;
    str_t password;
    unsigned char p[MD5_DIGEST_LENGTH << 1];

    rc = want_image(&image);
    if (!rc) return 0;

    if (image)
    {
        size_t i;

        str_t captcha_path = pair_array_lookup(&robot.conf, str_from("CAPTCHA"));
        if (str_empty(captcha_path)) captcha_path = str_from("captcha.jpeg");

        rc = download_image(captcha_path);
        if (!rc) return 0;

        fprintf(stdout, "Please input verify_code(in %s)\n", captcha_path.ptr);
        fflush(stdout);
        scanf("%s", (char*)robot.verify_code);
        for (i = 0; i < VERIFY_LEN; ++i) robot.verify_code[i] = toupper(robot.verify_code[i]);
        robot.verify_code[VERIFY_LEN] = 0;
    }

    password = pair_array_lookup(&robot.conf, str_from("PASSWORD"));
    encode_password(password, robot.verify_code, robot.bits, p);

    rc = login_step1(p);
    if (!rc) return 0;

    rc = login_step2();
    if (!rc) return 0;

    return 1;
}

int main(int argc, char* argv[])
{
    signal(SIGSEGV, crash_sig);
    signal(SIGABRT, crash_sig);
    signal(SIGHUP, dummy_sig);

    int i;

    init();
    for (i = 1; i < argc; ++i)
    {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0)
        {
            show_usage();
            break;
        }
        else if (strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--conf") == 0)
        {
            if (i + 1 < argc) robot.conf_file = str_dup(argv[++i]);
            else
            {
                fprintf(stderr, "Error: -c or --conf argument given but no config file specified.\n");
                return 1;
            }
        }
    }
    run();
    str_free(robot.conf_file);
    return 0;
}

