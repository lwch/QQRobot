#include <auto_config.h>
#include <auto_module.h>

#include <signal.h>
#include <string.h>

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
    memcpy(robot.verify_code, check_response[1].ptr, VERIFY_LEN);
    bits_from_str(check_response[2], robot.bits);
    if (strcmp(check_response[0].ptr, "0") == 0) *want = 0;
    else *want = 1;

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
    int rc;
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
    return 1;
}

int main(int argc, char* argv[])
{
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

