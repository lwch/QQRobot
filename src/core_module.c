#include <auto_config.h>
#include <auto_module.h>

#include <errno.h>
#include <execinfo.h>
#include <signal.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#include <cJSON.h>

#include "common.h"
#include "qqrobot.h"

robot_t robot;

module_t core_module = {
    MODULE_DEFAULT_VERSION,
    str("core_module"),
    NULL,
    NULL,
    NULL,
    NULL
};

extern module_t conf_module;

extern int parse_conf_file(str_t path);

static void change_ptwebqq(str_t* post_data, cJSON* ptwebqq);
static void route_result(cJSON* result);

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

static void bits_from_str(str_t str, uchar bits[BITS_LEN])
{
    size_t i;
    for (i = 0; i < BITS_LEN; ++i)
    {
        uchar ch1 = tolower(str.ptr[(i << 2) + 2]);
        uchar ch2 = tolower(str.ptr[(i << 2) + 3]);
        ch1 = (ch1 >= 'a' && ch1 <= 'f') ? ch1 - 'a' + 10 : ch1 - '0';
        ch2 = (ch2 >= 'a' && ch2 <= 'f') ? ch2 - 'a' + 10 : ch2 - '0';
        bits[i] = (ch1 << 4) | ch2;
    }
}

static void encode_password(const str_t password, const char verify_code[VERIFY_LEN], const uchar bits[BITS_LEN], uchar out[MD5_DIGEST_LENGTH << 1])
{
    str_t password_bin = str2bin(password);
    uchar md5_src_1[MD5_DIGEST_LENGTH + BITS_LEN] = {0};
    uchar md5_src_2[(MD5_DIGEST_LENGTH << 1) + VERIFY_LEN] = {0};
    uchar md5_src[MD5_DIGEST_LENGTH << 1] = {0};
    size_t i;

    memcpy(md5_src_1, password_bin.ptr, MD5_DIGEST_LENGTH);
    memcpy(md5_src_1 + MD5_DIGEST_LENGTH, bits, BITS_LEN);
    str_free(password_bin);
    md5_str(md5_src_1, MD5_DIGEST_LENGTH + BITS_LEN, md5_src);
    memcpy(md5_src_2, md5_src, MD5_DIGEST_LENGTH << 1);
    for (i = 0; i < VERIFY_LEN; ++i)
    {
        md5_src_2[(MD5_DIGEST_LENGTH << 1) + i] = toupper(verify_code[i]);
    }
    md5_str(md5_src_2, (MD5_DIGEST_LENGTH << 1) + VERIFY_LEN, out);
}

static ullong get_friend_number(ullong uin)
{
    str_t str_cookie = empty_str;
    curl_data_t data_uin = empty_curl_data;
    char str_uin[128] = {0};
    char* url;
    cJSON* cjson_uin;
    ullong ret = 0;

    sprintf(str_uin, "%llu", uin);
    url = calloc(sizeof("http://s.web2.qq.com/api/get_friend_uin2?tuin=&verifysession=&type=1&code=&vfwebqq=&t=1401621019") + strlen(str_uin) + robot.vfwebqq.len, 1);
    strcpy(url, "http://s.web2.qq.com/api/get_friend_uin2?tuin=");
    strcat(url, str_uin);
    strcat(url, "&verifysession=&type=1&code=&vfwebqq=");
    strncat(url, robot.vfwebqq.ptr, robot.vfwebqq.len);
    strcat(url, "&t=1401621019");
    str_cookie = cookie_to_str(&robot.cookie);
    ret = get_request_with_cookie(url, 1, "./pems/s.web2.qq.com.pem", str_cookie.ptr, &data_uin, NULL);
    if (!ret) goto end;

    cjson_uin = cJSON_Parse(data_uin.data.ptr);
    if (cJSON_GetObjectItem(cjson_uin, "retcode")->valueint == 0)
    {
        cJSON* cjson_result = cJSON_GetObjectItem(cjson_uin, "result");
        ret = cJSON_GetObjectItem(cjson_result, "account")->valuedouble;
    }
    cJSON_Delete(cjson_uin);

end:
    str_free(str_cookie);
    curl_data_free(&data_uin);
    free(url);
    return ret;
}

static ullong get_group_number(ullong uin)
{
    str_t str_cookie = empty_str;
    curl_data_t data_uin = empty_curl_data;
    char str_uin[128] = {0};
    char* url;
    cJSON* cjson_uin;
    ullong ret = 0;

    sprintf(str_uin, "%llu", uin);
    url = calloc(sizeof("http://s.web2.qq.com/api/get_friend_uin2?tuin=&verifysession=&type=4&code=&vfwebqq=&t=1401621019") + strlen(str_uin) + robot.vfwebqq.len, 1);
    strcpy(url, "http://s.web2.qq.com/api/get_friend_uin2?tuin=");
    strcat(url, str_uin);
    strcat(url, "&verifysession=&type=4&code=&vfwebqq=");
    strncat(url, robot.vfwebqq.ptr, robot.vfwebqq.len);
    strcat(url, "&t=1401621019");
    str_cookie = cookie_to_str(&robot.cookie);
    ret = get_request_with_cookie(url, 1, "./pems/s.web2.qq.com.pem", str_cookie.ptr, &data_uin, NULL);
    if (!ret) goto end;

    cjson_uin = cJSON_Parse(data_uin.data.ptr);
    if (cJSON_GetObjectItem(cjson_uin, "retcode")->valueint == 0)
    {
        cJSON* cjson_result = cJSON_GetObjectItem(cjson_uin, "result");
        ret = cJSON_GetObjectItem(cjson_result, "account")->valuedouble;
    }
    cJSON_Delete(cjson_uin);

end:
    str_free(str_cookie);
    curl_data_free(&data_uin);
    free(url);
    return ret;
}

static str_t fetch_content(cJSON* cjson_content)
{
    int size = cJSON_GetArraySize(cjson_content);
    int i;
    str_t ret = empty_str;

    for (i = 0; i < size; ++i)
    {
        cJSON* item = cJSON_GetArrayItem(cjson_content, i);
        if (item->type == cJSON_String) str_cat(&ret, item->valuestring);
    }
    ret.ptr[--ret.len] = 0;
    return ret;
}

static void merge_cookie_to_robot(pair_array_t* header)
{
    pair_array_t cookie = empty_pair_array;
    size_t i;
    for (i = 0; i < header->count; ++i)
    {
        if (strcmp("Set-Cookie", header->keys[i].ptr) == 0)
        {
            fetch_cookie(header->vals[i], &cookie);
            merge_cookie(&robot.cookie, &cookie);
            pair_array_free(&cookie);
        }
    }
}

static int want_image(int* want)
{
    curl_data_t data_check = empty_curl_data;
    curl_header_t header_check = empty_curl_header;
    str_t number = pair_array_lookup(&robot.conf, str_from("QQ"));
    char* url = malloc(sizeof("https://ssl.ptlogin2.qq.com/check?uin=&appid=1003903&r=0.14233942252344134") + number.len);
    str_t* check_response = NULL;
    int rc = 1;
    size_t check_response_count = 0;

    url[0] = 0;
    strcpy(url, "https://ssl.ptlogin2.qq.com/check?uin=");
    strncat(url, number.ptr, number.len);
    strcat(url, "&appid=1003903&r=0.14233942252344134");
    rc = get_request(url, 1, "./pems/ssl.ptlogin2.qq.com.pem", &data_check, &header_check);
    if (!rc)
    {
        fprintf(stderr, "Call check error!!!!\n");
        goto end;
    }

    merge_cookie_to_robot(&header_check);

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
    str_t number = pair_array_lookup(&robot.conf, str_from("QQ"));
    char* url = malloc(sizeof("https://ssl.captcha.qq.com/getimage?aid=1003903&r=0.577911190026398&uin=") + number.len);
    int rc = 1;

    FILE* fp;

    url[0] = 0;
    strcpy(url, "https://ssl.captcha.qq.com/getimage?aid=1003903&r=0.577911190026398&uin=");
    strncat(url, number.ptr, number.len);

    rc = get_request(url, 1, "./pems/ssl.captcha.qq.com.pem", &data_getimage, &header_getimage);
    if (!rc)
    {
        fprintf(stderr, "Call getimage error!!!!\n");
        goto end;
    }

    merge_cookie_to_robot(&header_getimage);

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
    int rc = 1;

    rc = get_request(url, 0, NULL, NULL, &header_proxy);
    if (!rc)
    {
        fprintf(stderr, "Call proxy error!!!!\n");
        goto end;
    }

    merge_cookie_to_robot(&header_proxy);
end:
    pair_array_free(&header_proxy);
    return rc;
}

static int login_step1(const unsigned char password[MD5_DIGEST_LENGTH << 1])
{
    curl_data_t data_login = empty_curl_data;
    curl_header_t header_login = empty_curl_header;
    str_t number = pair_array_lookup(&robot.conf, str_from("QQ"));
    str_t cookie_str;
    char* url = malloc(sizeof("https://ssl.ptlogin2.qq.com/login?u=&p=&verifycode=&webqq_type=10&remember_uin=1&login2qq=1&aid=1003903&u1=http%3A%2F%2Fweb2.qq.com%2Floginproxy.html%3Flogin2qq%3D1%26webqq_type%3D10&h=1&ptredirect=0&ptlang=2052&daid=164&from_ui=1&pttype=1&dumy=&fp=loginerroralert&action=6-53-32873&mibao_css=m_webqq&t=4&g=1&js_type=0&js_ver=10077&login_sig=qBpuWCs9dlR9awKKmzdRhV8TZ8MfupdXF6zyHmnGUaEzun0bobwOhMh6m7FQjvWA") + (MD5_DIGEST_LENGTH << 1) + VERIFY_LEN + number.len);
    str_t* login_response = NULL;
    int rc = 1;
    size_t login_response_count = 0;

    url[0] = 0;
    strcpy(url, "https://ssl.ptlogin2.qq.com/login?u=");
    strncat(url, number.ptr, number.len);
    strcat(url, "&p=");
    strncat(url, (char*)password, MD5_DIGEST_LENGTH << 1);
    strcat(url, "&verifycode=");
    strncat(url, robot.verify_code, VERIFY_LEN);
    strcat(url, "&webqq_type=10&remember_uin=1&login2qq=1&aid=1003903&u1=http%3A%2F%2Fweb2.qq.com%2Floginproxy.html%3Flogin2qq%3D1%26webqq_type%3D10&h=1&ptredirect=0&ptlang=2052&daid=164&from_ui=1&pttype=1&dumy=&fp=loginerroralert&action=6-53-32873&mibao_css=m_webqq&t=4&g=1&js_type=0&js_ver=10077&login_sig=qBpuWCs9dlR9awKKmzdRhV8TZ8MfupdXF6zyHmnGUaEzun0bobwOhMh6m7FQjvWA");

    cookie_str = cookie_to_str(&robot.cookie);

    rc = get_request_with_cookie(url, 1, "./pems/ssl.ptlogin2.qq.com.pem", cookie_str.ptr, &data_login, &header_login);
    if (!rc)
    {
        fprintf(stderr, "Call login error!!!!\n");
        goto end;
    }

    merge_cookie_to_robot(&header_login);
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
    curl_data_t data_login2 = empty_curl_data;
    curl_header_t header_login2 = empty_curl_header;
    cJSON* cjson_login2_post = cJSON_CreateObject();
    cJSON *cjson_login2 = NULL, *cjson_result;
    str_t post_data = empty_str, tmp = empty_str;
    str_t cookie_str;
    str_t status = pair_array_lookup(&robot.conf, str_from("STATUS"));
    int rc = 1;

    cJSON_AddStringToObject(cjson_login2_post, "status", status.ptr);
    cJSON_AddStringToObject(cjson_login2_post, "ptwebqq", robot.ptwebqq.ptr);
    cJSON_AddStringToObject(cjson_login2_post, "passwd_sig", "");
    cJSON_AddStringToObject(cjson_login2_post, "clientid", CLIENTID);
    cJSON_AddNullToObject(cjson_login2_post, "psessionid");
    post_data.ptr = cJSON_PrintUnformatted(cjson_login2_post);
    post_data.len = strlen(post_data.ptr);
    str_cpy(&tmp, str_from("r="));
    str_ncat(&tmp, post_data.ptr, post_data.len);
    str_cat(&tmp, "&clientid="CLIENTID"&psessionid=null");
    str_free(post_data);
    urlencode(tmp, &post_data);

    cookie_str = cookie_to_str(&robot.cookie);
    rc = post_request_with_cookie("https://d.web2.qq.com/channel/login2", 1, "./pems/d.web2.qq.com.pem", post_data.ptr, cookie_str.ptr, &data_login2, &header_login2);
    if (!rc)
    {
        fprintf(stderr, "Call login2 error!!!!\n");
        goto end;
    }

    merge_cookie_to_robot(&header_login2);

    cjson_login2 = cJSON_Parse(data_login2.data.ptr);
    if (cJSON_GetObjectItem(cjson_login2, "retcode")->valueint != 0)
    {
        rc = 0;
        fprintf(stderr, "login2 faild!!!!\n");
        fprintf(stderr, "%s\n", data_login2.data.ptr);
        goto end;
    }

    cjson_result = cJSON_GetObjectItem(cjson_login2, "result");
    str_free(robot.session);
    robot.session = str_dup(cJSON_GetObjectItem(cjson_result, "psessionid")->valuestring);
    str_free(robot.vfwebqq);
    robot.vfwebqq = str_dup(cJSON_GetObjectItem(cjson_result, "vfwebqq")->valuestring);
end:
    curl_data_free(&data_login2);
    pair_array_free(&header_login2);
    cJSON_Delete(cjson_login2_post);
    cJSON_Delete(cjson_login2);
    str_free(post_data);
    str_free(tmp);
    str_free(cookie_str);
    return rc;
}

static void init_data()
{
    size_t i, j, k;

    robot.conf_file = static_empty_str;
    robot.conf = static_empty_pair_array;

    memset(robot.verify_code, 0, VERIFY_LEN);
    memset(robot.bits, 0, BITS_LEN);
    robot.ptwebqq = static_empty_str;
    robot.cookie = static_empty_pair_array;
    robot.session = static_empty_str;
    robot.vfwebqq = static_empty_str;
    robot.mongoc_client = NULL;
    robot.mongoc_database = NULL;
    robot.run = 1;

    robot.received_message_funcs_count = robot.received_group_message_funcs_count = 0;
    for (i = 0;; ++i)
    {
        if (modules[i] == NULL) break;
        if (modules[i]->received_message) ++robot.received_message_funcs_count;
        if (modules[i]->received_group_message) ++robot.received_group_message_funcs_count;
    }
    robot.received_message_funcs = malloc(sizeof(*robot.received_message_funcs) * robot.received_message_funcs_count);
    robot.received_group_message_funcs = malloc(sizeof(*robot.received_group_message_funcs) * robot.received_group_message_funcs_count);
    for (i = j = k = 0;; ++i)
    {
        if (modules[i] == NULL) break;
        if (modules[i]->received_message) robot.received_message_funcs[j++] = modules[i]->received_message;
        if (modules[i]->received_group_message) robot.received_group_message_funcs[k++] = modules[i]->received_group_message;
    }
}

static void make_poll_post_data(str_t* post_data)
{
    cJSON* cjson_poll_post = cJSON_CreateObject();
    str_t tmp = empty_str;

    cJSON_AddStringToObject(cjson_poll_post, "clientid", CLIENTID);
    cJSON_AddStringToObject(cjson_poll_post, "psessionid", robot.session.ptr);
    cJSON_AddNumberToObject(cjson_poll_post, "key", 0);
    cJSON_AddItemToObject(cjson_poll_post, "ids", cJSON_CreateArray());
    post_data->ptr = cJSON_PrintUnformatted(cjson_poll_post);
    post_data->len = strlen(post_data->ptr);
    cJSON_Delete(cjson_poll_post);
    str_cpy(&tmp, str_from("r="));
    str_ncat(&tmp, post_data->ptr, post_data->len);
    str_cat(&tmp, "&clientid="CLIENTID"&psessionid=");
    str_ncat(&tmp, robot.session.ptr, robot.session.len);
    str_free(*post_data);
    urlencode(tmp, post_data);
    str_free(tmp);
}

static void route(str_t* cookie_str, curl_data_t* data_poll, curl_header_t* header_poll)
{
    cJSON* cjson_poll;

    merge_cookie_to_robot(header_poll);

    cjson_poll = cJSON_Parse(data_poll->data.ptr);
    switch (cJSON_GetObjectItem(cjson_poll, "retcode")->valueint)
    {
    case 116:
        change_ptwebqq(cookie_str, cJSON_GetObjectItem(cjson_poll, "p"));
        break;
    case 0:
        route_result(cJSON_GetObjectItem(cjson_poll, "result"));
        break;
    }
}

static int config_check()
{
    if (!str_empty(robot.conf_file))
    {
        if (!parse_conf_file(robot.conf_file)) return 0;
    }
    else
    {
        fprintf(stderr, "Please input configure file!!!!\n");
        return 0;
    }
    if (str_empty(pair_array_lookup(&robot.conf, str_from("QQ"))) || str_empty(pair_array_lookup(&robot.conf, str_from("PASSWORD"))))
    {
        fprintf(stderr, "Please input configure file with QQ and PASSWORD!!!!\n");
        return 0;
    }
    if (str_empty(pair_array_lookup(&robot.conf, str_from("DB_HOST"))))
    {
        fprintf(stdout, "Warning: Unset DB_HOST variable, the default value is 127.0.0.1!!!!\n");
        fflush(stdout);
        pair_array_append_pointers(&robot.conf, "DB_HOST", "127.0.0.1");
    }
    if (str_empty(pair_array_lookup(&robot.conf, str_from("DB_NAME"))))
    {
        fprintf(stdout, "Warning: Unset DB_NAME variable, the default value is qqrobot!!!!\n");
        fflush(stdout);
        pair_array_append_pointers(&robot.conf, "DB_NAME", "qqrobot");
    }
    return 1;
}

static int init()
{
    str_t tmp = empty_str;
    str_t host = pair_array_lookup(&robot.conf, str_from("DB_HOST"));
    str_t name = pair_array_lookup(&robot.conf, str_from("DB_NAME"));

    int rc = 1;

    str_cat(&tmp, "mongodb://");
    str_ncat(&tmp, host.ptr, host.len);
    robot.mongoc_client = mongoc_client_new(tmp.ptr);
    if (robot.mongoc_client == NULL)
    {
        rc = 0;
        fprintf(stderr, "mongoc_client_new(\"%s\") error!!!!\n", tmp.ptr);
        goto end;
    }

    robot.mongoc_database = mongoc_client_get_database(robot.mongoc_client, name.ptr);
    if (robot.mongoc_database == NULL)
    {
        rc = 0;
        fprintf(stderr, "mongoc_client_get_database(\"%s\") error!!!!\n", name.ptr);
        goto end;
    }

    {
        mongoc_collection_t* message_collection;
        mongoc_index_opt_t opt;
        bson_error_t error;
        bson_t keys;

        message_collection = mongoc_database_get_collection(robot.mongoc_database, "message");
        if (message_collection == NULL)
        {
            rc = 0;
            fprintf(stderr, "mongoc_database_get_collection(\"message\") error!!!!\n");
            goto end;
        }

        mongoc_index_opt_init(&opt);

        // from+type 做联合索引
        bson_init(&keys);
        BSON_APPEND_INT32(&keys, "from", 1);
        BSON_APPEND_INT32(&keys, "type", 1);

        if (!mongoc_collection_create_index(message_collection, &keys, &opt, &error)) MONGOC_WARNING("%s\n", error.message);

        bson_destroy(&keys);

        // time 做逆序索引
        bson_init(&keys);
        BSON_APPEND_INT32(&keys, "time", -1);

        if (!mongoc_collection_create_index(message_collection, &keys, &opt, &error)) MONGOC_WARNING("%s\n", error.message);

        bson_destroy(&keys);

        // content 做全文索引
        bson_init(&keys);
        BSON_APPEND_UTF8(&keys, "content", "text");

        if (!mongoc_collection_create_index(message_collection, &keys, &opt, &error)) MONGOC_WARNING("%s\n", error.message);

        bson_destroy(&keys);
    }

    {
        mongoc_collection_t* unprocessed_collection;
        mongoc_index_opt_t opt;
        bson_error_t error;
        bson_t keys;

        unprocessed_collection = mongoc_database_get_collection(robot.mongoc_database, "unprocessed");
        if (unprocessed_collection == NULL)
        {
            rc = 0;
            fprintf(stderr, "mongoc_database_get_collection(\"unprocessed\") error!!!!\n");
            goto end;
        }

        mongoc_index_opt_init(&opt);

        // time 做逆序索引
        bson_init(&keys);
        BSON_APPEND_INT32(&keys, "time", -1);

        if (!mongoc_collection_create_index(unprocessed_collection, &keys, &opt, &error)) MONGOC_WARNING("%s\n", error.message);

        bson_destroy(&keys);
    }

end:
    str_free(tmp);
    return rc;
}

static void run()
{
    size_t i, modules_count;
    str_t post_data = empty_str, cookie_str;
    curl_data_t data_poll = empty_curl_data;
    curl_header_t header_poll = empty_curl_header;

    for (modules_count = 0;; ++modules_count)
    {
        if (modules[modules_count] == NULL) break;
        if (modules[modules_count]->module_init) modules[modules_count]->module_init();
    }

    if (!config_check()) return;
    if (!init()) return;
    if (!login()) return;

    make_poll_post_data(&post_data);

    cookie_str = cookie_to_str(&robot.cookie);

    while (robot.run)
    {
        if (!post_request_with_cookie("https://d.web2.qq.com/channel/poll2", 1, "./pems/d.web2.qq.com.pem", post_data.ptr, cookie_str.ptr, &data_poll, &header_poll)) continue;

        route(&cookie_str, &data_poll, &header_poll);

        curl_data_free(&data_poll);
        pair_array_free(&header_poll);
    }

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
    int image = 0;
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
        if (scanf("%s", (char*)robot.verify_code) > VERIFY_LEN)
        {
            fprintf(stderr, "verify_code is to long!!!!\n");
            return 0;
        }
        for (i = 0; i < VERIFY_LEN; ++i) robot.verify_code[i] = toupper(robot.verify_code[i]);
        robot.verify_code[VERIFY_LEN] = 0;
    }

    password = pair_array_lookup(&robot.conf, str_from("PASSWORD"));
    encode_password(password, robot.verify_code, robot.bits, p);

    rc = login_step1(p);
    if (!rc) return 0;

    rc = login_step2();
    if (!rc) return 0;

    fprintf(stdout, "Login successed ...\n");
    fflush(stdout);

    return 1;
}

static void encrypt()
{
    unsigned char ch;
    unsigned char password[256];
    int i;
    int err;
    unsigned char md5[MD5_DIGEST_LENGTH << 1];
    struct termios term;

    if (tcgetattr(STDIN_FILENO, &term)==-1)
    {
        perror("Cannot get the attribution of the terminal");
        return;
    }
    term.c_lflag &= ~(ICANON | ECHO | ECHOE | ECHOK | ECHONL | ECHOPRT | ECHOKE | ICRNL);
    err = tcsetattr(STDIN_FILENO, TCSAFLUSH, &term);
    if (err == -1 && err == EINTR)
    {
        perror("Cannot set the attribution of the terminal");
        return;
    }

    i = 0;
    fprintf(stdout, "Please input password：");
    do
    {
        ch = getchar();
        if (ch == '\n' || ch == '\r') break;
        if (ch == 127 && i > 0) --i;
        else
        {
            if (i >= 254)
            {
                fprintf(stderr, "Password length must less than 255!!!!\n");
                return;
            }
            password[i++] = ch;
        }
    } while (1);
    fprintf(stdout, "\n");
    password[i] = 0;
    md5_str(password, i, md5);
    fprintf(stdout, "%-32.32s\n", md5);
}

static void change_ptwebqq(str_t* cookie_str, cJSON* ptwebqq)
{
#ifdef _DEBUG
    fprintf(stdout, "change ptwebqq: %s\n", ptwebqq->valuestring);
    fflush(stdout);
#endif
    pair_array_set(&robot.cookie, str_from("ptwebqq"), str_from(ptwebqq->valuestring));
    robot.ptwebqq = pair_array_lookup(&robot.cookie, str_from("ptwebqq"));
    str_free(*cookie_str);
    *cookie_str = cookie_to_str(&robot.cookie);
}

static void dump_message(ullong number, str_t type, str_t content)
{
    bson_t document;
    bson_error_t error;
    time_t t;
    mongoc_collection_t* collection = mongoc_database_get_collection(robot.mongoc_database, "message");

    time(&t);
    bson_init(&document);
    BSON_APPEND_INT64(&document, "from", number);
    BSON_APPEND_UTF8(&document, "type", type.ptr);
    BSON_APPEND_UTF8(&document, "content", content.ptr);
    BSON_APPEND_TIME_T(&document, "time", t);
    if (!mongoc_collection_insert(collection, MONGOC_INSERT_NONE, &document, NULL, &error)) MONGOC_WARNING("%s\n", error.message);
    bson_destroy(&document);
}

static void route_result(cJSON* result)
{
    cJSON* cjson_current;
    size_t i;
    for (cjson_current = result->child; cjson_current; cjson_current = cjson_current->next)
    {
        if (strcmp(cJSON_GetObjectItem(cjson_current, "poll_type")->valuestring, "message") == 0)
        {
            cJSON* cjson_value = cJSON_GetObjectItem(cjson_current, "value");
            ullong from_uin = cJSON_GetObjectItem(cjson_value, "from_uin")->valuedouble;
            ullong number = get_friend_number(from_uin);
            str_t content = fetch_content(cJSON_GetObjectItem(cjson_value, "content"));
            dump_message(number, str_from("friend_message"), content);
#ifdef _DEBUG
            fprintf(stdout, "Received message from: %llu\nContent: %s\n", number, content.ptr);
            fflush(stdout);
#endif

            for (i = 0; i < robot.received_message_funcs_count; ++i) robot.received_message_funcs[i](from_uin, number, content);
            str_free(content);
        }
        else if (strcmp(cJSON_GetObjectItem(cjson_current, "poll_type")->valuestring, "group_message") == 0)
        {
            cJSON* cjson_value = cJSON_GetObjectItem(cjson_current, "value");
            ullong from_uin = cJSON_GetObjectItem(cjson_value, "from_uin")->valuedouble;
            ullong number = get_group_number(cJSON_GetObjectItem(cjson_value, "group_code")->valuedouble);
            str_t content = fetch_content(cJSON_GetObjectItem(cjson_value, "content"));
            dump_message(number, str_from("group_message"), content);
#ifdef _DEBUG
            fprintf(stdout, "Received group_message from: %llu\nContent: %s\n", number, content.ptr);
            fflush(stdout);
#endif

            for (i = 0; i < robot.received_group_message_funcs_count; ++i) robot.received_group_message_funcs[i](from_uin, number, content);
            str_free(content);
        }
        else
        {
            bson_t document;
            bson_t content;
            bson_error_t error;
            time_t t;
            char* ptr = cJSON_PrintUnformatted(cjson_current);
            mongoc_collection_t* collection = mongoc_database_get_collection(robot.mongoc_database, "unprocessed");

            time(&t);
            if (!bson_init_from_json(&content, ptr, strlen(ptr), &error))
            {
                MONGOC_WARNING("%s\n", error.message);
                return;
            }
            bson_init(&document);
            BSON_APPEND_TIME_T(&document, "time", t);
            BSON_APPEND_DOCUMENT(&document, "content", &content);
            if (!mongoc_collection_insert(collection, MONGOC_INSERT_NONE, &document, NULL, &error)) MONGOC_WARNING("%s\n", error.message);
            bson_destroy(&document);
            bson_destroy(&content);
        }
    }
}

int main(int argc, char* argv[])
{
    signal(SIGSEGV, crash_sig);
    signal(SIGABRT, crash_sig);
    signal(SIGHUP, dummy_sig);

    int i;

    init_data();
    for (i = 1; i < argc; ++i)
    {
        if (strcmp(argv[i], "-e") == 0 || strcmp(argv[i], "--encrypt") == 0)
        {
            encrypt();
            return 0;
        }
    }
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

