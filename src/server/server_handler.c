//server_handler.c

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include "fastcommon/logger.h"
#include "fastcommon/sockopt.h"
#include "fastcommon/shared_func.h"
#include "fastcommon/pthread_func.h"
#include "fastcommon/sched_thread.h"
#include "fastcommon/ioevent_loop.h"
#include "fastcommon/json_parser.h"
#include "sf/sf_util.h"
#include "sf/sf_func.h"
#include "sf/sf_nio.h"
#include "sf/sf_global.h"
#include "common/fken_proto.h"
#include "server_global.h"
#include "question_search.h"
#include "server_handler.h"

int server_handler_init()
{
    return 0;
}

int server_handler_destroy()
{   
    return 0;
}

static int parse_answer_conditions(struct fast_task_info *task,
        const FKENRequestInfo *request, FKENResponseInfo *response,
        const int kv_count, string_t *question,
        AnswerConditionArray *conditions)
{
    int i;
    int current_body_len;
    char *p;
    FKENProtoQuestionSearchKVEntry *kv_entry;
    key_value_pair_t *kv_pair;

    p = question->str + question->len;
    current_body_len = p - (task->data + sizeof(FKENProtoHeader));

    kv_pair = conditions->kv_pairs;
    for (i=0; i<kv_count; i++) {
        current_body_len += sizeof(FKENProtoQuestionSearchKVEntry);
        if (request->body_len < current_body_len) {
            response->error.length = sprintf(response->error.message,
                    "request body length: %d < %d",
                    request->body_len, current_body_len);
            return EINVAL;
        }

        kv_entry = (FKENProtoQuestionSearchKVEntry *)p;
        kv_pair->key.len = kv_entry->key_len;
        kv_pair->value.len = kv_entry->value_len;
        if (kv_pair->key.len == 0) {
            response->error.length = sprintf(response->error.message,
                    "invalid key length: %d", kv_pair->key.len);
            return EINVAL;
        }

        current_body_len += kv_pair->key.len + kv_pair->value.len;
        if (request->body_len < current_body_len) {
            response->error.length = sprintf(response->error.message,
                    "request body length: %d < %d",
                    request->body_len, current_body_len);
            return EINVAL;
        }
        kv_pair->key.str = kv_entry->key;
        kv_pair->value.str = kv_pair->key.str + kv_pair->key.len;

        p = kv_pair->value.str + kv_pair->value.len;
        kv_pair++;
    }

    if (request->body_len != current_body_len) {
        response->error.length = sprintf(response->error.message,
                "request body length: %d != %d",
                request->body_len, current_body_len);
        return EINVAL;
    }
    conditions->count = kv_count;
    return 0;
}

static int output_answers(struct fast_task_info *task,
        FKENResponseInfo *response, QASearchResultArray *results)
{
    FKENProtoQuestionSearchRespHeader *resp_header;
    QASearchResultEntry *entry;
    QASearchResultEntry *end;
    FKENProtoAnswerEntry *answer_entry;
    char *p;
    int result;
    int expect_size;

    resp_header = (FKENProtoQuestionSearchRespHeader *)(task->data +
            sizeof(FKENProtoHeader));
    resp_header->answer_count = results->count;

    response->body_len = sizeof(FKENProtoQuestionSearchRespHeader);
    end = results->entries + results->count;
    for (entry=results->entries; entry<end; entry++) {
        response->body_len += sizeof(FKENProtoAnswerEntry) + entry->answer->len;
    }

    expect_size = sizeof(FKENProtoHeader) + response->body_len;
    if (expect_size > task->size) {
        if ((result=free_queue_set_buffer_size(task, expect_size)) != 0) {
            response->error.length = sprintf(response->error.message,
                    "free_queue_set_buffer_size to %d fail", expect_size);
            return result;
        }
    }

    p = (char *)resp_header + sizeof(FKENProtoQuestionSearchRespHeader);
    for (entry=results->entries; entry<end; entry++) {
        answer_entry = (FKENProtoAnswerEntry *)p;
        long2buff(entry->id, answer_entry->id);
        short2buff(entry->answer->len, answer_entry->answer_len);
        p += sizeof(FKENProtoAnswerEntry);
        memcpy(answer_entry->answer, entry->answer->str, entry->answer->len);

        p += entry->answer->len;
    }

    return 0;
}

static int fken_proto_deal_question_search(struct fast_task_info *task,
        const FKENRequestInfo *request, FKENResponseInfo *response)
{
    int result;
    FKENProtoQuestionSearchReqHeader *req_header;
    key_value_pair_t kv_pairs[FKEN_MAX_CONDITION_COUNT];
    AnswerConditionArray conditions;
    QASearchResultArray results;
    string_t question;
    int kv_count;

    if ((result=FKEN_PROTO_CHECK_MIN_BODY_LEN(task, request, response,
                    sizeof(FKENProtoQuestionSearchReqHeader))) != 0)
    {
        return result;
    }

    req_header = (FKENProtoQuestionSearchReqHeader *)(task->data +
            sizeof(FKENProtoHeader));
    kv_count = req_header->kv_count;
    question.len = req_header->question_len;

    if (kv_count < 0 || kv_count > FKEN_MAX_CONDITION_COUNT) {
        response->error.length = sprintf(response->error.message,
                "invalid key-value count: %d", kv_count);
        return EINVAL;
    }
    if (question.len <= 0) {
        response->error.length = sprintf(response->error.message,
                "invalid question length: %d", question.len);
        return EINVAL;
    }
    question.str = req_header->question;

    conditions.kv_pairs = kv_pairs;
    if ((result=parse_answer_conditions(task, request, response,
                    kv_count, &question, &conditions)) != 0)
    {
        return result;
    }

    if ((result=question_search(&question, &conditions, &results)) != 0) {
        if (result != ENOENT) {
            return result;
        }
    }

    if ((result=output_answers(task, response, &results)) != 0) {
        return result;
    }

    response->response_done = true;
    response->cmd = FKEN_PROTO_QUESTION_SEARCH_RESP;
    return 0;
}

int fken_server_deal_task(struct fast_task_info *task)
{
    FKENProtoHeader *proto_header;
    FKENRequestInfo request;
    FKENResponseInfo response;
    int result;
    int r;
    int time_used;
    char buff[16];
    int64_t tbegin;

    tbegin = get_current_time_us();
    response.cmd = FKEN_PROTO_ACK;
    response.body_len = 0;
    response.log_error = true;
    response.error.length = 0;
    response.error.message[0] = '\0';
    response.response_done = false;

    request.cmd = ((FKENProtoHeader *)task->data)->cmd;
    request.body_len = task->length - sizeof(FKENProtoHeader);
    switch (request.cmd) {
        case FKEN_PROTO_ACTIVE_TEST_REQ:
            response.cmd = FKEN_PROTO_ACTIVE_TEST_RESP;
            result = fken_proto_deal_actvie_test(task, &request, &response);
            break;
        case FKEN_PROTO_QUESTION_SEARCH_REQ:
            result = fken_proto_deal_question_search(task, &request, &response);
            break;
        default:
            response.error.length = sprintf(response.error.message,
                    "unkown cmd: %d", request.cmd);
            result = -EINVAL;
            break;
    }

    if (response.log_error && response.error.length > 0) {
        logError("file: "__FILE__", line: %d, "
                "client ip: %s, cmd: %d, body length: %d, %s", __LINE__,
                task->client_ip, request.cmd, request.body_len,
                response.error.message);
    }

    proto_header = (FKENProtoHeader *)task->data;
    if (!response.response_done) {
        response.body_len = response.error.length;
        if (response.error.length > 0) {
            memcpy(task->data + sizeof(FKENProtoHeader),
                    response.error.message, response.error.length);
        }
    }

    proto_header->status = result >= 0 ? result : -1 * result;
    proto_header->cmd = response.cmd;
    int2buff(response.body_len, proto_header->body_len);
    task->length = sizeof(FKENProtoHeader) + response.body_len;

    r = sf_send_add_event(task);
    time_used = (int)(get_current_time_us() - tbegin);
    if (time_used > 100) {
        lwarning("timed used to process a request is %s us, "
                "cmd: %d, req body len: %d, resp body len: %d",
                int_to_comma_str(time_used, buff), request.cmd,
                request.body_len, response.body_len);
    }

    ldebug("client ip: %s, req cmd: %d, req body_len: %d, "
            "resp cmd: %d, status: %d, resp body_len: %d, "
            "time used: %s us",  task->client_ip,
            request.cmd, request.body_len,
            response.cmd, proto_header->status,
            response.body_len, int_to_comma_str(time_used, buff));

    return r == 0 ? result : r;
}
