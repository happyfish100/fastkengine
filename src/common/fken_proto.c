
#include <errno.h>
#include "fastcommon/shared_func.h"
#include "fastcommon/connection_pool.h"
#include "fastcommon/ini_file_reader.h"
#include "fken_proto.h"
#include "fken_types.h"
#include "fastcommon/sockopt.h"

void fken_proto_init()
{
}

int fken_proto_set_body_length(struct fast_task_info *task)
{
    task->length = buff2int(((FKENProtoHeader *)task->data)->body_len);
    return 0;
}

int fken_proto_deal_actvie_test(struct fast_task_info *task,
        const FKENRequestInfo *request, FKENResponseInfo *response)
{
    return FKEN_PROTO_EXPECT_BODY_LEN(task, request, response, 0);
}

int fken_check_response(ConnectionInfo *conn, FKENProtoHeader *resp_header,
        int network_timeout, unsigned char resp_cmd, int *body_len,
        char *error_info, const int error_size)
{
    int blen;

    blen = buff2int(resp_header->body_len);
    if (body_len != NULL) {
        *body_len = blen;
    }
    if (resp_header->cmd == resp_cmd && resp_header->status == 0) {
        *error_info = '\0';
        return 0;
    }

    if (error_info != NULL) {
        if (blen > 0) {
            if (blen >= error_size) {
                blen = error_size - 1;
            }

            memset(error_info, 0, error_size);
            tcprecvdata_nb(conn->sock, error_info,
                    blen, network_timeout);
            *(error_info + blen) = '\0';
        } else {
            *error_info = '\0';
        }
    } else {
        *error_info = '\0';
    }

    return resp_header->status != 0 ? resp_header->status : EINVAL;
}

int send_and_recv_response_header(ConnectionInfo *conn, char *data,
        const int len, const int network_timeout, FKENProtoHeader *header)
{
    int ret;

    if ((ret=tcpsenddata_nb(conn->sock, data, len, network_timeout)) != 0) {
        logError("file: "__FILE__", line: %d, "
                "tcpsenddata_nb fail, errno: %d, error info: %s",
                __LINE__, ret, strerror(ret));
        return ret;
    }
    if ((ret=tcprecvdata_nb(conn->sock, header,
            sizeof(FKENProtoHeader), network_timeout)) != 0) {
        logError("file: "__FILE__", line: %d, "
                "tcprecvdata_nb fail, errno: %d, error info: %s",
                __LINE__, ret, strerror(ret));
        return ret;
    }

    return 0;
}

int fken_send_active_test(ConnectionInfo *conn, const int network_timeout,
        char *error_info, const int error_size)
{
    int ret;
    FKENProtoHeader req_header;
    FKENProtoHeader resp_header;

    fken_set_header(&req_header, FKEN_PROTO_ACTIVE_TEST_REQ, 0);
    ret = send_and_recv_response_header(conn, (char *)&req_header,
            sizeof(FKENProtoHeader), network_timeout, &resp_header);
    if (ret == 0) {
        ret = fken_check_response(conn, &resp_header, network_timeout,
                FKEN_PROTO_ACTIVE_TEST_RESP, NULL,
                error_info, error_size);
    }

    return ret;
}
