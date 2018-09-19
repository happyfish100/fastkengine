#ifndef _FKEN_PROTO_H
#define _FKEN_PROTO_H

#include "fastcommon/fast_task_queue.h"
#include "fastcommon/shared_func.h"
#include "fastcommon/logger.h"
#include "fastcommon/connection_pool.h"
#include "fastcommon/ini_file_reader.h"
#include "fken_types.h"

#define FKEN_SERVER_DEFAULT_INNER_PORT   10000
#define FKEN_SERVER_DEFAULT_OUTER_PORT   10000

#define FKEN_PROTO_ACK                    6

#define FKEN_PROTO_ACTIVE_TEST_REQ       35
#define FKEN_PROTO_ACTIVE_TEST_RESP      36

#define FKEN_PROTO_QUESTION_SEARCH_REQ   41
#define FKEN_PROTO_QUESTION_SEARCH_RESP  42

typedef struct fken_proto_header {
    char body_len[4];       //body length
    unsigned char cmd;      //the command code
    unsigned char status;   //status to store errno
    char padding[2];
} FKENProtoHeader;

typedef struct fken_proto_question_kv_entry {
    unsigned char key_len;
    unsigned char value_len;
    char key[0];
    /* char *value;    //value = key + key_len  */
} FKENProtoQuestionSearchKVEntry;

typedef struct fken_proto_question_search_req_header {
    unsigned char kv_count;
    unsigned char question_len;
    char question[0];
} FKENProtoQuestionSearchReqHeader;

typedef struct fken_proto_answer_entry {
    char answer_len[2];
    char answer[0];
} FKENProtoAnswerEntry;

typedef struct fken_proto_question_search_resp_header {
    unsigned char answer_count;
} FKENProtoQuestionSearchRespHeader;

#ifdef __cplusplus
extern "C" {
#endif

void fken_proto_init();

int fken_proto_set_body_length(struct fast_task_info *task);

int fken_proto_deal_actvie_test(struct fast_task_info *task,
        const FKENRequestInfo *request, FKENResponseInfo *response);

int send_and_recv_response_header(ConnectionInfo *conn, char *data, int len,
        FKENResponseInfo *response, int network_timeout);

void fken_proto_response_extract (FKENProtoHeader *header_pro,
        FKENResponseInfo *response);

int fken_send_active_test(ConnectionInfo *conn, FKENResponseInfo *response,
        int network_timeout);

int fken_check_response(ConnectionInfo *conn,
        FKENResponseInfo *response, int network_timeout,
        unsigned char resp_cmd);

static inline void fken_set_header(FKENProtoHeader *header,
        unsigned char cmd, int body_len)
{
    header->cmd = cmd;
    int2buff(body_len, header->body_len);
}

static inline int fken_proto_expect_body_length(struct fast_task_info *task,
        const FKENRequestInfo *request, FKENResponseInfo *response,
        const int expect_body_length)
{
    if (request->body_len != expect_body_length) {
        response->error.length = sprintf(response->error.message,
                "request body length: %d != %d",
                request->body_len, expect_body_length);
        return EINVAL;
    }

    return 0;
}

static inline int fken_proto_check_min_body_length(struct fast_task_info *task,
        const FKENRequestInfo *request, FKENResponseInfo *response,
        const int min_body_length)
{
    if (request->body_len < min_body_length) {
        response->error.length = sprintf(response->error.message,
                "request body length: %d < %d",
                request->body_len, min_body_length);
        return EINVAL;
    }

    return 0;
}

static inline int fken_proto_check_max_body_length(struct fast_task_info *task,
        const FKENRequestInfo *request, FKENResponseInfo *response,
        const int max_body_length)
{
    if (request->body_len > max_body_length) {
        response->error.length = sprintf(response->error.message,
                "request body length: %d > %d",
                request->body_len, max_body_length);
        return EINVAL;
    }

    return 0;
}

static inline int fken_proto_check_body_length(struct fast_task_info *task,
        const FKENRequestInfo *request, FKENResponseInfo *response,
        const int min_body_length, const int max_body_length)
{
    int result;
    if ((result=fken_proto_check_min_body_length(task, request, response,
            min_body_length)) != 0)
    {
        return result;
    }
    return fken_proto_check_max_body_length(task, request, response,
            max_body_length);
}

#define FKEN_PROTO_EXPECT_BODY_LEN(task, request, response, expect_length) \
    fken_proto_expect_body_length(task, request, response, expect_length)

#define FKEN_PROTO_CHECK_MIN_BODY_LEN(task, request, response, min_length) \
    fken_proto_check_min_body_length(task, request, response, min_length)

#define FKEN_PROTO_CHECK_MAX_BODY_LEN(task, request, response, max_length) \
    fken_proto_check_max_body_length(task, request, response, max_length)

#define FKEN_PROTO_CHECK_BODY_LEN(task, request, response, min_length, max_length) \
    fken_proto_check_body_length(task, request, response, \
            min_length, max_length)

#ifdef __cplusplus
}
#endif

#endif
