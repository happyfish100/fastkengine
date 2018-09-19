
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

int fken_check_response(ConnectionInfo *conn, FKENResponseInfo *response,
        int network_timeout, unsigned char resp_cmd)
{
    if (response->cmd == resp_cmd && response->status == 0) {
        return 0;
    }

    if (response->body_len > 0) {
        if (response->body_len >= sizeof(response->error.message)) {
            response->body_len = sizeof(response->error.message) - 1;
        }
        tcprecvdata_nb(conn->sock, response->error.message,
                response->body_len, network_timeout);
        response->error.message[response->body_len] = '\0';
    } else {
        response->error.message[0] = '\0';
    }
    return response->status != 0 ? response->status : EINVAL;
}

int send_and_recv_response_header(ConnectionInfo *conn, char *data, int len,
        FKENResponseInfo *response, int network_timeout)
{
    int ret;
    FKENProtoHeader header;

    if ((ret = tcpsenddata_nb(conn->sock, data, len, network_timeout)) != 0) {
        return ret;
    }
    if ((ret = tcprecvdata_nb(conn->sock, &header,
            sizeof(FKENProtoHeader), network_timeout)) != 0) {
        return ret;
    }
    return 0;
}

int fken_send_active_test(ConnectionInfo *conn, FKENResponseInfo *response,
        int network_timeout)
{
    int ret;
    FKENProtoHeader header;

    fken_set_header(&header, FKEN_PROTO_ACTIVE_TEST_REQ, 0);
    ret = send_and_recv_response_header(conn, (char *)&header,
            sizeof(FKENProtoHeader), response, network_timeout);
    if (ret == 0) {
        ret = fken_check_response(conn, response, network_timeout,
                FKEN_PROTO_ACTIVE_TEST_RESP);
    }

    return ret;
}
