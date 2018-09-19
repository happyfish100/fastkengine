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
#include "server_handler.h"

int server_handler_init()
{
    return 0;
}

int server_handler_destroy()
{   
    return 0;
}

int fken_server_deal_task(struct fast_task_info *task)
{
    FKENProtoHeader *proto_header;
    FKENRequestInfo request;
    FKENResponseInfo response;
    int result;
    int r;
    int64_t tbegin;
    int time_used;

    tbegin = get_current_time_ms();
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
    time_used = (int)(get_current_time_ms() - tbegin);
    if (time_used > 1000) {
        lwarning("timed used to process a request is %d ms, "
                "cmd: %d, req body len: %d, resp body len: %d",
                time_used, request.cmd,
                request.body_len, response.body_len);
    }

    ldebug("client ip: %s, req cmd: %d, req body_len: %d, "
            "resp cmd: %d, status: %d, resp body_len: %d, "
            "time used: %d ms",  task->client_ip,
            request.cmd, request.body_len,
            response.cmd, proto_header->status,
            response.body_len, time_used);

    return r == 0 ? result : r;
}
