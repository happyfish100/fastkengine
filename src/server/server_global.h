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
    char data_path[MAX_PATH_SIZE];
    int question_index_hashtable_buckets;
    int keyword_trie_top_hashtable_buckets;
} KEngineGlobalVariables;

#ifdef __cplusplus
extern "C" {
#endif

extern KEngineGlobalVariables g_server_vars;

int kengine_load_config_and_data(const char *filename);

#ifdef __cplusplus
}
#endif

#endif

