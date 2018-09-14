//server_global.h

#ifndef _SERVER_GLOBAL_H
#define _SERVER_GLOBAL_H

#include "fastcommon/common_define.h"
#include "fastcommon/ini_file_reader.h"
#include "fastcommon/ioevent.h"
#include "keyword_hashtable.h"
#include "wordsegment.h"
#include "keyword_index.h"

typedef struct kengine_global_variables {
    KeywordHashtableContext kh_context;
    KeywordIndexContext ki_context;
} KEngineGlobalVariables;

#ifdef __cplusplus
extern "C" {
#endif

extern KEngineGlobalVariables g_server_vars;

#ifdef __cplusplus
}
#endif

#endif

