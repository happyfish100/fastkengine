//server_handler.h

#ifndef FKEN_SERVER_HANDLER_H
#define FKEN_SERVER_HANDLER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "fastcommon/fast_task_queue.h"

#ifdef __cplusplus
extern "C" {
#endif

int server_handler_init();
int server_handler_destroy();
int fken_server_deal_task(struct fast_task_info *task);

#ifdef __cplusplus
}
#endif

#endif
