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
static int received_message(ullong uin, ullong number, msg_content_array_t* content);
static int received_group_message(ullong uin, ullong number, msg_content_array_t* content);

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

static int is_study_msg(msg_content_array_t* content, msg_content_array_t* left, msg_content_array_t* right)
{
    enum
    {
        APPEND_LEFT,
        APPEND_RIGHT
    } mode = APPEND_LEFT;
    size_t i;

    for (i = 0; i < content->count; ++i)
    {
        switch (content->vals[i].type)
        {
        case MSG_CONTENT_TYPE_STRING:
            if (str_split_count(content->vals[i].string.ptr, "=>") > 1)
            {
                str_t* array = NULL;
                size_t array_count = str_split(content->vals[i].string.ptr, "=>", &array);
                size_t j = 0;

                if (str_empty(array[j])) ++j;
                if (mode == APPEND_LEFT)
                {
                    msg_content_array_append_string(left, array[j++].ptr);
                    mode = APPEND_RIGHT;
                }
                if (mode == APPEND_RIGHT && j < array_count)
                {
                    if (str_empty(array[j])) ++j;
                    else msg_content_array_append_string(right, array[j++].ptr);
                }

                str_array_free(array, array_count);
                free(array);
                if (j < array_count) return 0;
            }
            else
            {
                msg_content_array_append_string(mode == APPEND_LEFT ? left : right, content->vals[i].string.ptr);
            }
            break;
        case MSG_CONTENT_TYPE_FACE:
            msg_content_array_append_face(mode == APPEND_LEFT ? left : right, content->vals[i].face_id);
            break;
        default:
            break;
        }
    }
    return 1;
}

static void make_study_update(const char* left, const char* right, bson_t* bson)
{
    cJSON *cjson_left = cJSON_Parse(left), *cjson_right = cJSON_Parse(right);
    char* str;
    bson_error_t error;

    cJSON_AddItemToObject(cjson_left, "answer", cJSON_DetachItemFromObject(cjson_right, "answer"));
    str = cJSON_PrintUnformatted(cjson_left);
    if (!bson_init_from_json(bson, str, strlen(str), &error)) MONGOC_WARNING("%s\n", error.message);

    cJSON_Delete(cjson_left);
    cJSON_Delete(cjson_right);
}

static study_result_e study(msg_content_array_t* content)
{
    study_result_e ret = STUDY_SUCCESS;
    msg_content_array_t left = empty_msg_content_array, right = empty_msg_content_array;

    if (is_study_msg(content, &left, &right))
    {
        char *str_left, *str_right;
        bson_t query, update;
        bson_error_t error;

        if (msg_content_array_empty(right))
        {
            ret = STUDY_FAILD;
            goto end;
        }

        str_left = msg_content_array_to_json_object_string(&left, "question");
        str_right = msg_content_array_to_json_object_string(&right, "answer");

        if (!bson_init_from_json(&query, str_left, strlen(str_left), &error)) MONGOC_WARNING("%s\n", error.message);
        make_study_update(str_left, str_right, &update);

        if (!mongoc_collection_find_and_modify(conf.study_collection, &query, NULL, &update, NULL, 0, 1, false, NULL, &error)) MONGOC_WARNING("%s\n", error.message);

        free(str_left);
        free(str_right);
        bson_destroy(&query);
        bson_destroy(&update);
    }
    else ret = STUDY_USAGE;
end:
    msg_content_array_free(&left);
    msg_content_array_free(&right);
#ifdef _DEBUG
    fprintf(stdout, "study retval: %d\n", ret);
    fflush(stdout);
#endif
    return ret;
}

static void lookup_question_filter(msg_content_array_t* content)
{
    str_t old;

    // 去除最左侧的#
    old = content->vals[0].string;
    if (old.len == 1) // 第一块仅有一个#
    {
        memmove(content->vals, content->vals + 1, sizeof(*content->vals) * content->count - 1);
        if (content->count == 0)
        {
            str_free(old);
            return;
        }
        --content->count;
    }
    else // #后带内容
    {
        content->vals[0].string = str_ndup(old.ptr + 1, old.len - 1);
    }
    str_free(old);

    // 最后面做trim
    old = content->vals[content->count - 1].string;
    str_rtrim(old.ptr, old.len, &content->vals[content->count - 1].string);
    str_free(old);
    if (str_empty(content->vals[content->count - 1].string)) --content->count;
}

static msg_content_array_t lookup(msg_content_array_t* content)
{
    char* str_question = msg_content_array_to_json_object_string(content, "question");
    msg_content_array_t ret = empty_msg_content_array;
    bson_t query, fields;
    mongoc_cursor_t* cursor;
    bson_error_t error;
    const bson_t* doc;
    char* res;
    cJSON* cjson_result;

#ifdef _DEBUG
    fprintf(stdout, "lookup query: %s\n", str_question);
    fflush(stdout);
#endif

    bson_init(&fields);

    if (!bson_init_from_json(&query, str_question, strlen(str_question), &error)) MONGOC_WARNING("%s\n", error.message);

    BSON_APPEND_INT32(&fields, "answer", 1);

    if (mongoc_collection_count(conf.study_collection, MONGOC_QUERY_NONE, &query, 0, 0, NULL, &error) == 0 && error.code)
    {
        MONGOC_WARNING("%s\n", error.message);
        goto end;
    }

    cursor = mongoc_collection_find(conf.study_collection, MONGOC_QUERY_NONE, 0, 0, 0, &query, &fields, NULL);
    if (!mongoc_cursor_next(cursor, &doc)) goto end;

    res = bson_as_json(doc, NULL);
    cjson_result = cJSON_Parse(res);
    ret = msg_content_array_from_json_value(cJSON_GetObjectItem(cjson_result, "answer"));
    cJSON_Delete(cjson_result);
    bson_free(res);
    mongoc_cursor_destroy(cursor);
end:
    free(str_question);
    bson_destroy(&query);
    bson_destroy(&fields);
    return ret;
}

static int send_friend_message(ullong uin, msg_content_array_t* message)
{
    curl_data_t data_send = empty_curl_data;
    cJSON* cjson_send_post = cJSON_CreateObject();
    cJSON* cjson_content;
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
        cjson_content = msg_content_array_to_json_value(message);
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

static int received_message(ullong uin, ullong number, msg_content_array_t* content)
{
    msg_content_array_t send = empty_msg_content_array;
    int rc = 1;

    if (content->vals[0].type != MSG_CONTENT_TYPE_STRING || content->vals[0].string.ptr[0] != '#') return 1;
    if (conf.disallow_all_friends)
    {
        size_t i;
        for (i = 0; i < conf.disallow_all_friends; ++i)
        {
            if (conf.allow_friends[i] == number) break;
        }
        if (i == conf.disallow_all_friends) return 1;
    }
    lookup_question_filter(content);
    switch (study(content))
    {
    case STUDY_SUCCESS:
        msg_content_array_append_string(&send, "我已经学会了...");
        break;
    case STUDY_USAGE:
        msg_content_array_append_string(&send, "发送\"#问题=>答案\"来让机器人学会回答这个问题 ...");
        break;
    default:
        if (!msg_content_array_empty(*content))
        {
            send = lookup(content);
            if (msg_content_array_empty(send)) msg_content_array_append_string(&send, "对不起，我还不知道如何回答这个问题 ...\n请发送\"#问题=>答案\"来让机器人学会回答这个问题 ...");
        }
        else msg_content_array_append_string(&send, "对不起，我还不知道如何回答这个问题 ...\n请发送\"#问题=>答案\"来让机器人学会回答这个问题 ...");
        break;
    }
    rc = send_friend_message(uin, &send);
    msg_content_array_free(&send);
    return rc;
}

static int send_group_message(ullong uin, msg_content_array_t* message)
{
    curl_data_t data_send = empty_curl_data;
    cJSON* cjson_send_post = cJSON_CreateObject();
    cJSON* cjson_content;
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
        cjson_content = msg_content_array_to_json_value(message);
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

static int received_group_message(ullong uin, ullong number, msg_content_array_t* content)
{
    msg_content_array_t send = empty_msg_content_array;
    int rc = 1;

    if (content->vals[0].type != MSG_CONTENT_TYPE_STRING || content->vals[0].string.ptr[0] != '#') return 1;
    if (conf.disallow_all_groups)
    {
        size_t i;
        for (i = 0; i < conf.disallow_all_groups; ++i)
        {
            if (conf.allow_groups[i] == number) break;
        }
        if (i == conf.disallow_all_groups) return 1;
    }
    lookup_question_filter(content);
    switch (study(content))
    {
    case STUDY_SUCCESS:
        msg_content_array_append_string(&send, "我已经学会了...");
        break;
    case STUDY_USAGE:
        msg_content_array_append_string(&send, "发送\"#问题=>答案\"来让机器人学会回答这个问题 ...");
        break;
    default:
        if (!msg_content_array_empty(*content))
        {
            send = lookup(content);
            if (msg_content_array_empty(send)) msg_content_array_append_string(&send, "对不起，我还不知道如何回答这个问题 ...\n请发送\"#问题=>答案\"来让机器人学会回答这个问题 ...");
        }
        else msg_content_array_append_string(&send, "对不起，我还不知道如何回答这个问题 ...\n请发送\"#问题=>答案\"来让机器人学会回答这个问题 ...");
        break;
    }
    rc = send_group_message(uin, &send);
    msg_content_array_free(&send);
    return rc;
}

