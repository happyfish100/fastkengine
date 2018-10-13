#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/poll.h>
#include "fastcommon/shared_func.h"
#include "fastcommon/sockopt.h"
#include "fastcommon/logger.h"
#include "sf/sf_func.h"
#include "sf/sf_util.h"
#include "fken_proto.h"
#include "fken_client.h"

static int client_load_from_conf_file(FKenClient *client, const char *filename)
{
	IniContext ini_context;
    char *sz_max_pkg_size;
    int64_t max_pkg_size;
	int result;

	memset(&ini_context, 0, sizeof(IniContext));
	if ((result=iniLoadFromFile(filename, &ini_context)) != 0) {
		logError("file: "__FILE__", line: %d, "
			"load conf file \"%s\" fail, ret code: %d",
			__LINE__, filename, result);
		return result;
	}

	do {
		client->connect_timeout = iniGetIntValue(NULL, "connect_timeout",
				&ini_context, DEFAULT_CONNECT_TIMEOUT);
		if (client->connect_timeout <= 0) {
			client->connect_timeout = DEFAULT_CONNECT_TIMEOUT;
		}

		client->network_timeout = iniGetIntValue(NULL, "network_timeout",
				&ini_context, DEFAULT_NETWORK_TIMEOUT);
		if (client->network_timeout <= 0) {
			client->network_timeout = DEFAULT_NETWORK_TIMEOUT;
		}
	
        sz_max_pkg_size = iniGetStrValue(NULL, "max_pkg_size", &ini_context);
        if (sz_max_pkg_size == NULL) {
            max_pkg_size = FKEN_DEFAULT_NETWORK_BUFFER_SIZE;
        } else {
            if ((result=parse_bytes(sz_max_pkg_size, 1, &max_pkg_size)) != 0) {
                return result;
            }
            if (max_pkg_size < 1024) {
                logWarning("file: "__FILE__", line: %d, "
                        "max_pkg_size: %d is too small, set to 1024",
                        __LINE__, (int)max_pkg_size);
                max_pkg_size = 1024;
            }
        }
        client->max_pkg_size = max_pkg_size;

        if ((result=conn_pool_load_server_info(&ini_context, filename,
                        "server", &client->conn,
                        FKEN_SERVER_DEFAULT_INNER_PORT)) != 0)
        {
            break;
        }

        logDebug("FastKEngine connect_timeout=%ds, "
			"network_timeout=%ds, max_pkg_size=%d KB, "
			"server=%s:%d",
			client->connect_timeout,
			client->network_timeout,
            client->max_pkg_size / 1024,
            client->conn.ip_addr, client->conn.port);

	} while (0);

	iniFreeContext(&ini_context);
	return result;
}

int fken_client_init(FKenClient *client, const char *config_filename)
{
    int result;

    fken_proto_init();
    srand(time(NULL));
    result = client_load_from_conf_file(client, config_filename);
    if (result != 0) {
        logError("file: %s, line: %d load config file fail, "
                "error: %s", __FILE__, __LINE__, strerror(result));
        return result;
    }
    client->buff = (char *)malloc(client->max_pkg_size);
    if (client->buff == NULL) {
        logError("file: "__FILE__", line: %d, "
                "malloc %d bytes fail", __LINE__, client->max_pkg_size);
        return ENOMEM;
    }

    client->conn.sock = -1;
    return result;
}

void fken_client_destroy(FKenClient* client)
{
    if (client->conn.sock >= 0) {
        conn_pool_disconnect_server(&client->conn);
    }
    if (client->buff != NULL) {
        free(client->buff);
        client->buff = NULL;
    }
}

static inline int fken_client_check_conn(FKenClient *client)
{
    if (client->conn.sock >= 0) {
        return 0;
    }

    return conn_pool_connect_server(&client->conn,
            client->connect_timeout);
}

static int question_search_req_pack(FKenClient *client,
        const string_t *question, const key_value_pair_t *vars,
        const int var_count, const int answer_format, int *buff_len)
{
    FKENProtoQuestionSearchReqHeader *req_header;
    const key_value_pair_t *kv_pair;
    const key_value_pair_t *kv_end;
    char *p;
    FKENProtoQuestionSearchKVEntry *kv_entry;
    int expect_size;

    req_header =  (FKENProtoQuestionSearchReqHeader *)(client->buff +
            sizeof(FKENProtoHeader));

    if (question->len <= 0) {
		logError("file: "__FILE__", line: %d, "
                "question is empty", __LINE__);
        return EINVAL;
    }
    if (question->len > 255) {
		logError("file: "__FILE__", line: %d, "
                "question length: %d is too long, exceeds 255",
                __LINE__, question->len);
        return EOVERFLOW;
    }
    if (var_count > FKEN_MAX_CONDITION_COUNT) {
		logError("file: "__FILE__", line: %d, "
                "too many condions: %d, exceeds %d", __LINE__,
                var_count, FKEN_MAX_CONDITION_COUNT);
        return EOVERFLOW;
    }
    expect_size = (req_header->question - client->buff) + question->len;
    if (expect_size > client->max_pkg_size) {
		logError("file: "__FILE__", line: %d, "
                "max_pkg_size: %d too small, expect size: %d",
                __LINE__, client->max_pkg_size, expect_size);
        return ENOSPC;
    }

    req_header->question_len = question->len;
    req_header->kv_count = var_count;
    req_header->answer_format = answer_format;
    memcpy(req_header->question, question->str, question->len);

    kv_end = vars + var_count;
    for (kv_pair=vars; kv_pair<kv_end; kv_pair++) {
        expect_size += sizeof(FKENProtoQuestionSearchKVEntry) +
            kv_pair->key.len + kv_pair->value.len;
    }
    if (expect_size > client->max_pkg_size) {
		logError("file: "__FILE__", line: %d, "
                "max_pkg_size: %d too small, expect size: %d",
                __LINE__, client->max_pkg_size, expect_size);
        return ENOSPC;
    }
    
    p = req_header->question + question->len;
    for (kv_pair=vars; kv_pair<kv_end; kv_pair++) {
        kv_entry = (FKENProtoQuestionSearchKVEntry *)p;
        kv_entry->key_len = kv_pair->key.len;
        kv_entry->value_len = kv_pair->value.len;
        memcpy(kv_entry->key, kv_pair->key.str, kv_pair->key.len);
        memcpy(kv_entry->key + kv_pair->key.len,
                kv_pair->value.str, kv_pair->value.len);

        p += sizeof(FKENProtoQuestionSearchKVEntry) +
            kv_pair->key.len + kv_pair->value.len;
    }

    *buff_len = expect_size;
    return 0;
}

static int question_search_resp_unpack(FKenClient *client,
        const int body_len, FKenAnswerArray *answer_array)
{
    FKENProtoQuestionSearchRespHeader *result_header;
    FKENProtoAnswerEntry *proto_entry;
    char *p;
    int answer_len;
    int i;

    result_header = (FKENProtoQuestionSearchRespHeader *)client->buff;
    if (result_header->answer_count > FKEN_MAX_ANSWER_COUNT) {
        logError("file: "__FILE__", line: %d, "
                "too many answers: %d exceeds %d", __LINE__,
                result_header->answer_count, FKEN_MAX_ANSWER_COUNT);
        return EOVERFLOW;
    }

    p = client->buff + sizeof(FKENProtoQuestionSearchRespHeader);
    for (i=0; i<result_header->answer_count; i++) {
        proto_entry = (FKENProtoAnswerEntry *)p;
        answer_len = buff2short(proto_entry->answer_len);
        if (answer_len < 0) {
            logError("file: "__FILE__", line: %d, "
                    "invalid answer length: %d",
                    __LINE__, answer_len);
            return EINVAL;
        }

        answer_array->answers[i].id = buff2long(proto_entry->id);
        answer_array->answers[i].answer.str = proto_entry->answer;
        answer_array->answers[i].answer.len = answer_len;
        p += sizeof(FKENProtoAnswerEntry) + answer_len;
        if ((int)(p - client->buff) > body_len) {
            logError("file: "__FILE__", line: %d, "
                    "real body length: %d > "
                    "body length: %d in header", __LINE__,
                    (int)(p - client->buff), body_len);
            return EINVAL;
        }
    }

    if ((int)(p - client->buff) != body_len) {
        logError("file: "__FILE__", line: %d, "
                "real body length: %d != "
                "body length: %d in header", __LINE__,
                (int)(p - client->buff), body_len);
        return EINVAL;
    }

    answer_array->count = result_header->answer_count;
    return 0;
}

int fken_client_question_search(FKenClient *client, const string_t *question,
    const key_value_pair_t *vars, const int var_count, const int answer_format,
    FKenAnswerArray *answer_array)
{
	int result;
    int req_len;
    int body_len;
    FKENProtoHeader resp_header;
    char error_info[FKEN_ERROR_INFO_SIZE];

    if ((result=fken_client_check_conn(client)) != 0) {
        return result;
    }

    if ((result=question_search_req_pack(client, question, vars,
                    var_count, answer_format, &req_len)) != 0)
    {
        return result;
    }
    fken_set_header((FKENProtoHeader *)client->buff,
            FKEN_PROTO_QUESTION_SEARCH_REQ, req_len - sizeof(FKENProtoHeader));

    do {
        if ((result=send_and_recv_response_header(&client->conn, client->buff,
                        req_len, client->network_timeout, &resp_header)) != 0)
        {
            break;
        }

        if ((result=fken_check_response(&client->conn, &resp_header,
                        client->network_timeout,
                        FKEN_PROTO_QUESTION_SEARCH_RESP, &body_len,
                        error_info, sizeof(error_info))) != 0)
        {
            break;
        }

        if (body_len < sizeof(FKENProtoQuestionSearchRespHeader)) {
            logError("file: "__FILE__", line: %d, "
                    "body length: %d is too small",
                    __LINE__, body_len);
            result = EINVAL;
            break;
        }

        if (body_len > client->max_pkg_size) {
            logError("file: "__FILE__", line: %d, "
                    "body length: %d is too large, "
                    "exceeds max_pkg_size: %d", __LINE__,
                    body_len, client->max_pkg_size);
            result = EOVERFLOW;
            break;
        }

        if ((result=tcprecvdata_nb(client->conn.sock, client->buff,
                        body_len, client->network_timeout)) != 0)
        {
            break;
        }

        result = question_search_resp_unpack(client, body_len, answer_array);
    } while (0);

    if (result != 0) {
        conn_pool_disconnect_server(&client->conn);
    }

    return result;
}
