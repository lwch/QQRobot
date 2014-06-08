#include <auto_config.h>
#include <auto_module.h>

#include <cJSON.h>

#include "common.h"
#include "qqrobot.h"
#include "chat_module.h"

typedef enum
{
    STUDY_FAILD   = 0,
    STUDY_SUCCESS = 1,
    STUDY_USAGE   = 2
} study_result_e;

static chat_module_conf_t conf;

static int chat_module_begin();
static int chat_module_init();
static void chat_module_exit();
static int received_message(ullong uin, ullong number, str_t content);
static int received_group_message(ullong uin, ullong number, str_t content);

module_t chat_module = {
    MODULE_DEFAULT_VERSION,
    str("chat_module"),
    chat_module_begin,
    chat_module_init,
    chat_module_exit,
    received_message,
    received_group_message
};

static int chat_module_begin()
{
    conf.disallow_all_friends = conf.disallow_all_groups = 0;
    conf.allow_friends = conf.allow_groups = NULL;
    conf.msg_id = 43450001;
    return 1;
}

static int chat_module_init()
{
    conf_val_t allow_friends_val = conf_lookup(&robot.conf, str_from("CHAT_ALLOW_FRIEND"));
    conf_val_t allow_groups_val = conf_lookup(&robot.conf, str_from("CHAT_ALLOW_GROUP"));
    mongoc_index_opt_t opt;
    bson_error_t error;
    bson_t keys;

    int rc = 1;

    conf.study_collection = mongoc_database_get_collection(robot.mongoc_database, "chat_study");
    if (conf.study_collection == NULL)
    {
        rc = 0;
        fprintf(stderr, "mongoc_database_get_collection(\"chat_study\") error!!!!\n");
        goto end;
    }

    mongoc_index_opt_init(&opt);

    // question 做索引
    bson_init(&keys);
    BSON_APPEND_INT32(&keys, "question", 1);

    if (!mongoc_collection_create_index(conf.study_collection, &keys, &opt, &error)) MONGOC_WARNING("%s\n", error.message);

    bson_destroy(&keys);

    if (allow_friends_val.type == CONF_VALUE_TYPE_STRING && strcmp(allow_friends_val.string.ptr, "ALL") == 0)
    {
        conf.disallow_all_friends = 0;
    }
    else if (allow_friends_val.type == CONF_VALUE_TYPE_ARRAY)
    {
        size_t i;

        conf.disallow_all_friends = allow_friends_val.array.count;
        conf.allow_friends = malloc(sizeof(*conf.allow_friends) * conf.disallow_all_friends);
        for (i = 0; i < conf.disallow_all_friends; ++i)
        {
            conf.allow_friends[i] = atoll(allow_friends_val.array.array[i].ptr);
        }
    }
    else
    {
        fprintf(stdout, "Warning: Unset CHAT_ALLOW_FRIEND variable, the default value is ALL!!!!\n");
        fflush(stdout);
        conf.disallow_all_friends = 0;
    }

    if (allow_groups_val.type == CONF_VALUE_TYPE_STRING && strcmp(allow_groups_val.string.ptr, "ALL") == 0)
    {
        conf.disallow_all_groups = 0;
    }
    else if (allow_groups_val.type == CONF_VALUE_TYPE_ARRAY)
    {
        size_t i;

        conf.disallow_all_groups = allow_groups_val.array.count;
        conf.allow_groups = malloc(sizeof(*conf.allow_groups) * conf.disallow_all_groups);
        for (i = 0; i < conf.disallow_all_groups; ++i)
        {
            conf.allow_groups[i] = atoll(allow_groups_val.array.array[i].ptr);
        }
    }
    else
    {
        fprintf(stdout, "Warning: Unset CHAT_ALLOW_GROUP variable, the default value is ALL!!!!\n");
        fflush(stdout);
        conf.disallow_all_groups = 0;
    }

end:
    return rc;
}

static void chat_module_exit()
{
    if (conf.disallow_all_friends) free(conf.allow_friends);
    if (conf.disallow_all_groups) free(conf.allow_groups);
    conf.disallow_all_friends = conf.disallow_all_groups = 0;
    conf.allow_friends = conf.allow_groups = NULL;
}

static study_result_e study(str_t content)
{
    study_result_e ret = STUDY_SUCCESS;
    str_t* array = NULL;
    size_t array_count = str_split(content.ptr + 1, "=>", &array);

    if (array_count == 2)
    {
        str_t question, answer;
        bson_t query, update;
        bson_error_t error;

        str_trim(array[0].ptr, array[0].len, &question);
        str_trim(array[1].ptr, array[1].len, &answer);
        if (str_empty(question) || str_empty(answer))
        {
            ret = STUDY_USAGE;
            goto end;
        }

        bson_init(&query);
        bson_init(&update);

        BSON_APPEND_UTF8(&query, "question", question.ptr);

        BSON_APPEND_UTF8(&update, "question", question.ptr);
        BSON_APPEND_UTF8(&update, "answer", answer.ptr);

        if (!mongoc_collection_find_and_modify(conf.study_collection, &query, NULL, &update, NULL, 0, 1, false, NULL, &error)) MONGOC_WARNING("%s\n", error.message);

        bson_destroy(&query);
        bson_destroy(&update);
    }
    else if (array_count) ret = STUDY_USAGE;
    else ret = STUDY_FAILD;
end:
    str_array_free(array, array_count);
    free(array);
#ifdef _DEBUG
    fprintf(stdout, "study retval: %d\n", ret);
    fflush(stdout);
#endif
    return ret;
}

static str_t lookup(str_t content)
{
    str_t ret = empty_str;
    bson_t query, fields;
    mongoc_cursor_t* cursor;
    bson_error_t error;
    const bson_t* doc;
    char* res;

    bson_init(&query);
    bson_init(&fields);

    BSON_APPEND_UTF8(&query, "question", content.ptr + 1);

    BSON_APPEND_INT32(&query, "answer", 1);

    if (mongoc_collection_count(conf.study_collection, MONGOC_QUERY_NONE, &query, 0, 0, NULL, &error) == 0 && error.code)
    {
        MONGOC_WARNING("%s\n", error.message);
        goto end;
    }

    cursor = mongoc_collection_find(conf.study_collection, MONGOC_QUERY_NONE, 0, 0, 0, &query, &fields, NULL);
    if (!mongoc_cursor_next(cursor, &doc)) goto end;

    res = bson_as_json(doc, NULL);
    content = str_dup(res);
    bson_free(res);
    mongoc_cursor_destroy(cursor);
end:
    bson_destroy(&query);
    bson_destroy(&fields);
    return ret;
}

static int send_friend_message(ullong uin, str_t message)
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
    cJSON_AddNumberToObject(cjson_send_post, "msg_id", conf.msg_id++);
    cJSON_AddStringToObject(cjson_send_post, "clientid", CLIENTID);
    cJSON_AddStringToObject(cjson_send_post, "psessionid", robot.session.ptr);
    {
        cJSON_AddItemToArray(cjson_content, cJSON_CreateString(message.ptr));
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

    rc = post_request_with_cookie("https://d.web2.qq.com/channel/send_buddy_msg2", 1, "./pems/d.web2.qq.com.pem", post_data.ptr, cookie_str.ptr, &data_send, NULL);
    if (!rc)
    {
        fprintf(stderr, "Call send_buddy_msg2 error!!!!\n");
        goto end;
    }
end:
    curl_data_free(&data_send);
    cJSON_Delete(cjson_send_post);
    cJSON_Delete(cjson_content);
    free(str_content);
    str_free(post_data);
    str_free(tmp);
    return rc;
}

static int received_message(ullong uin, ullong number, str_t content)
{
    str_t send = empty_str;
    int rc = 1;

    if (content.len == 0 || content.ptr[0] != '#') return 1;
    if (conf.disallow_all_friends)
    {
        size_t i;
        for (i = 0; i < conf.disallow_all_friends; ++i)
        {
            if (conf.allow_friends[i] == number) break;
        }
        if (i == conf.disallow_all_friends) return 1;
    }
    switch (study(content))
    {
    case STUDY_SUCCESS:
        send = str_dup("我已经学会了 ...");
        break;
    case STUDY_USAGE:
        send = str_dup("发送\"#问题=>答案\"来让机器人学会回答这个问题 ...");
        break;
    default:
        send = lookup(content);
        if (str_empty(send)) send = str_dup("对不起，我还不知道如何回答这个问题 ...\n请发送\"#问题=>答案\"来让机器人学会回答这个问题 ...");
        break;
    }
    rc = send_friend_message(uin, send);
    str_free(send);
    return rc;
}

static int send_group_message(ullong uin, str_t content)
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
    cJSON_AddNumberToObject(cjson_send_post, "msg_id", conf.msg_id++);
    cJSON_AddStringToObject(cjson_send_post, "clientid", CLIENTID);
    cJSON_AddStringToObject(cjson_send_post, "psessionid", robot.session.ptr);
    {
        cJSON_AddItemToArray(cjson_content, cJSON_CreateString(content.ptr));
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

    rc = post_request_with_cookie("https://d.web2.qq.com/channel/send_qun_msg2", 1, "./pems/d.web2.qq.com.pem", post_data.ptr, cookie_str.ptr, &data_send, NULL);
    if (!rc)
    {
        fprintf(stderr, "Call send_qun_msg2 error!!!!\n");
        goto end;
    }
end:
    curl_data_free(&data_send);
    cJSON_Delete(cjson_send_post);
    cJSON_Delete(cjson_content);
    free(str_content);
    str_free(post_data);
    str_free(tmp);
    return rc;
}

static int received_group_message(ullong uin, ullong number, str_t content)
{
    str_t send = empty_str;
    int rc = 1;

    if (content.len == 0 || content.ptr[0] != '#') return 1;
    if (conf.disallow_all_groups)
    {
        size_t i;
        for (i = 0; i < conf.disallow_all_groups; ++i)
        {
            if (conf.allow_groups[i] == number) break;
        }
        if (i == conf.disallow_all_groups) return 1;
    }
    switch (study(content))
    {
    case STUDY_SUCCESS:
        send = str_dup("我已经学会了 ...");
        break;
    case STUDY_USAGE:
        send = str_dup("发送\"#问题=>答案\"来让机器人学会回答这个问题 ...");
        break;
    default:
        send = lookup(content);
        if (str_empty(send)) send = str_dup("对不起，我还不知道如何回答这个问题 ...\n请发送\"#问题=>答案\"来让机器人学会回答这个问题 ...");
        break;
    }
    rc = send_group_message(uin, send);
    str_free(send);
    return rc;
}

