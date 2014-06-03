#include <auto_config.h>
#include <auto_module.h>

#include <cJSON.h>

#include "common.h"
#include "qqrobot.h"

static int received_message(ullong uin, ullong number, str_t content);
static int received_group_message(ullong uin, ullong number, str_t content);

module_t chat_module = {
    MODULE_DEFAULT_VERSION,
    str("chat_module"),
    NULL,
    NULL,
    received_message,
    received_group_message
};

static int received_message(ullong uin, ullong number, str_t content)
{
    curl_data_t data_send = empty_curl_data;
    cJSON* cjson_send_post = cJSON_CreateObject();
    cJSON* cjson_content = cJSON_CreateArray();
    cJSON* cjson_content_font_array = cJSON_CreateArray();
    cJSON* cjson_content_font = cJSON_CreateObject();
    int array[] = {0, 0, 0};
    cJSON* cjson_content_font_style = cJSON_CreateIntArray(array, 3);
    char* str_content;
    str_t post_data = empty_str, tmp = empty_str;
    str_t cookie_str;
    int rc;

    cJSON_AddNumberToObject(cjson_send_post, "to", uin);
    cJSON_AddNumberToObject(cjson_send_post, "face", 0);
    cJSON_AddNumberToObject(cjson_send_post, "msg_id", 43450001);
    cJSON_AddStringToObject(cjson_send_post, "clientid", CLIENTID);
    cJSON_AddStringToObject(cjson_send_post, "psessionid", robot.session.ptr);
    {
        cJSON_AddItemToArray(cjson_content, cJSON_CreateString("Hello World."));
        cJSON_AddItemToArray(cjson_content, cJSON_CreateString(""));
        {
            {
                cJSON_AddStringToObject(cjson_content_font, "name", "宋体");
                cJSON_AddStringToObject(cjson_content_font, "size", "10");
                cJSON_AddItemToObject(cjson_content_font, "style", cjson_content_font_style);
                cJSON_AddStringToObject(cjson_content_font, "color", "000000");
            }
            cJSON_AddItemToArray(cjson_content_font_array, cJSON_CreateString("font"));
            cJSON_AddItemToArray(cjson_content_font_array, cjson_content_font);
        }
        cJSON_AddItemToArray(cjson_content, cjson_content_font_array);
    }
    str_content = cJSON_PrintUnformatted(cjson_content);
    cJSON_AddStringToObject(cjson_send_post, "content", str_content);

    post_data.ptr = cJSON_PrintUnformatted(cjson_send_post);
    post_data.len = strlen(post_data.ptr);
    str_cpy(&tmp, str_from("r="));
    str_ncat(&tmp, post_data.ptr, post_data.len);
    str_cat(&tmp, "&clientid="CLIENTID"&psessionid=");
    str_ncat(&tmp, robot.session.ptr, robot.session.len);
    str_free(post_data);
    urlencode(tmp, &post_data);

    cookie_str = cookie_to_str(&robot.cookie);

#ifdef _DEBUG
    fprintf(stdout, "post: %s\ndata: %s\ncookie: %s\n", "https://d.web2.qq.com/channel/send_buddy_msg2", post_data.ptr, cookie_str.ptr);
    fflush(stdout);
#endif
    rc = post_request_with_cookie("https://d.web2.qq.com/channel/send_buddy_msg2", 1, "./pems/d.web2.qq.com.pem", post_data.ptr, cookie_str.ptr, &data_send, NULL);
    if (!rc)
    {
        fprintf(stderr, "Call send_buddy_msg2 error!!!!\n");
        goto end;
    }
#ifdef _DEBUG
    fprintf(stdout, "result: %s\n\n", data_send.data.ptr);
    fflush(stdout);
#endif
end:
    curl_data_free(&data_send);
    cJSON_Delete(cjson_send_post);
    cJSON_Delete(cjson_content);
    free(str_content);
    str_free(post_data);
    str_free(tmp);
    return 1;
}

static int received_group_message(ullong uin, ullong number, str_t content)
{
    curl_data_t data_send = empty_curl_data;
    cJSON* cjson_send_post = cJSON_CreateObject();
    cJSON* cjson_content = cJSON_CreateArray();
    cJSON* cjson_content_font_array = cJSON_CreateArray();
    cJSON* cjson_content_font = cJSON_CreateObject();
    int array[] = {0, 0, 0};
    cJSON* cjson_content_font_style = cJSON_CreateIntArray(array, 3);
    char* str_content;
    str_t post_data = empty_str, tmp = empty_str;
    str_t cookie_str;
    int rc;

    cJSON_AddNumberToObject(cjson_send_post, "group_uin", uin);
    cJSON_AddNumberToObject(cjson_send_post, "msg_id", 43970001);
    cJSON_AddStringToObject(cjson_send_post, "clientid", CLIENTID);
    cJSON_AddStringToObject(cjson_send_post, "psessionid", robot.session.ptr);
    {
        cJSON_AddItemToArray(cjson_content, cJSON_CreateString("Hello World."));
        cJSON_AddItemToArray(cjson_content, cJSON_CreateString(""));
        {
            {
                cJSON_AddStringToObject(cjson_content_font, "name", "宋体");
                cJSON_AddStringToObject(cjson_content_font, "size", "10");
                cJSON_AddItemToObject(cjson_content_font, "style", cjson_content_font_style);
                cJSON_AddStringToObject(cjson_content_font, "color", "000000");
            }
            cJSON_AddItemToArray(cjson_content_font_array, cJSON_CreateString("font"));
            cJSON_AddItemToArray(cjson_content_font_array, cjson_content_font);
        }
        cJSON_AddItemToArray(cjson_content, cjson_content_font_array);
    }
    str_content = cJSON_PrintUnformatted(cjson_content);
    cJSON_AddStringToObject(cjson_send_post, "content", str_content);

    post_data.ptr = cJSON_PrintUnformatted(cjson_send_post);
    post_data.len = strlen(post_data.ptr);
    str_cpy(&tmp, str_from("r="));
    str_ncat(&tmp, post_data.ptr, post_data.len);
    str_cat(&tmp, "&clientid="CLIENTID"&psessionid=");
    str_ncat(&tmp, robot.session.ptr, robot.session.len);
    str_free(post_data);
    urlencode(tmp, &post_data);

    cookie_str = cookie_to_str(&robot.cookie);

#ifdef _DEBUG
    fprintf(stdout, "post: %s\ndata: %s\ncookie: %s\n", "https://d.web2.qq.com/channel/send_qun_msg2", post_data.ptr, cookie_str.ptr);
    fflush(stdout);
#endif
    rc = post_request_with_cookie("https://d.web2.qq.com/channel/send_qun_msg2", 1, "./pems/d.web2.qq.com.pem", post_data.ptr, cookie_str.ptr, &data_send, NULL);
    if (!rc)
    {
        fprintf(stderr, "Call send_qun_msg2 error!!!!\n");
        goto end;
    }
#ifdef _DEBUG
    fprintf(stdout, "result: %s\n\n", data_send.data.ptr);
    fflush(stdout);
#endif
end:
    curl_data_free(&data_send);
    cJSON_Delete(cjson_send_post);
    cJSON_Delete(cjson_content);
    free(str_content);
    str_free(post_data);
    str_free(tmp);
    return 1;
}

