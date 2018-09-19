#ifndef _FKEN_TYPES_SERVER_H
#define _FKEN_TYPES_SERVER_H

#include <time.h>
#include "fastcommon/common_define.h"

#define FKEN_ERROR_INFO_SIZE         256

typedef struct {
    unsigned char cmd;  //response command
    int body_len;       //response body length
} FKENRequestInfo;

typedef struct {
    struct {
        char message[FKEN_ERROR_INFO_SIZE];
        int length;
    } error;
    int status;
    int body_len;    //response body length
    bool response_done;
    bool log_error;
    unsigned char cmd;   //response command
} FKENResponseInfo;

#endif
