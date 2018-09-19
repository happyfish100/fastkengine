#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#include "fastcommon/ini_file_reader.h"
#include "fastcommon/shared_func.h"
#include "fastcommon/logger.h"
#include "sf/sf_global.h"
#include "sf/sf_service.h"
#include "question_index.h"
#include "qa_loader.h"
#include "question_search.h"
#include "server_global.h"

KEngineGlobalVariables g_server_vars;

#define KNOWLEDGE_BASE_FILE_EXT_STR ".ken"
#define KNOWLEDGE_BASE_FILE_EXT_LEN (sizeof(KNOWLEDGE_BASE_FILE_EXT_STR) - 1)

static int kengine_load_kbase(int *total_file_count)
{
#define FILE_COUNT_ONCE 1  //TODO

    struct dirent *dirp;
    DIR  *dp;
    char filenames_holder[FILE_COUNT_ONCE][MAX_PATH_SIZE];
    char *filenames[FILE_COUNT_ONCE];
    int result;
    int i;
    int file_len;
    int file_count;

    if ((dp=opendir(g_server_vars.data_path)) == NULL) {
        return errno != 0 ? errno : EIO;
    }

    for (i=0; i<FILE_COUNT_ONCE; i++) {
        filenames[i] = filenames_holder[i];
    }

    result = 0;
    while (1) {
        file_count = 0;
        while ((dirp = readdir(dp)) != NULL) {
            file_len = strlen(dirp->d_name);
            if (file_len <= KNOWLEDGE_BASE_FILE_EXT_LEN) {
                continue;
            }

            if (memcmp(dirp->d_name + file_len - KNOWLEDGE_BASE_FILE_EXT_LEN,
                        KNOWLEDGE_BASE_FILE_EXT_STR, KNOWLEDGE_BASE_FILE_EXT_LEN) != 0)
            {
                continue;
            }

            snprintf(filenames[file_count], MAX_PATH_SIZE,
                    "%s/%s", g_server_vars.data_path, dirp->d_name);
            if (++file_count == FILE_COUNT_ONCE) {
                break;
            }
        }

        if (file_count > 0) {
            if ((result=qa_loader_init(filenames, file_count)) != 0) {
                break;
            }
            *total_file_count += file_count;
        }
        if (file_count < FILE_COUNT_ONCE) {
            break;
        }
    }

    return result;
}

static int kengine_load_data(int *total_file_count)
{
    char similars_filename[MAX_PATH_SIZE];
    char *similars_buff;
    int64_t file_size;
    int result;
    SimilarKeywordsInput similars;

    snprintf(similars_filename, sizeof(similars_filename),
            "%s/similars.txt", g_server_vars.data_path);
    if ((result=getFileContent(similars_filename, &similars_buff,
                    &file_size)) != 0)
    {
        return result;
    }

    similars.lines = split(similars_buff, '\n', 0, &similars.count);
    init_combination_index_arrays();
    if ((result=question_index_init(&g_server_vars.ki_context,
                    g_server_vars.question_index_hashtable_buckets)) != 0)
    {
        return result;
    }

    result = keyword_hashtable_init(&g_server_vars.kh_context,
            g_server_vars.keyword_trie_top_hashtable_buckets, &similars);
    if (result != 0) {
        return result;
    }

    return kengine_load_kbase(total_file_count);
}

int kengine_load_config_and_data(const char *filename)
{
    IniContext ini_context;
    char *data_path;
    char config_str[256];
    int result;
    int total_file_count = 0;

    memset(&ini_context, 0, sizeof(IniContext));
    if ((result=iniLoadFromFile(filename, &ini_context)) != 0) {
        logError("file: "__FILE__", line: %d, "
                "load conf file \"%s\" fail, ret code: %d",
                __LINE__, filename, result);
        return result;
    }

    if ((result=sf_load_config("fast_kengined", filename, &ini_context,
                    KENGINE_DEFAULT_INNER_PORT,
                    KENGINE_DEFAULT_OUTER_PORT)) != 0)
    {
        return result;
    }

    data_path = iniGetStrValue(NULL, "data_path", &ini_context);
    if (data_path == NULL || *data_path == '\0') {
        logError("file: "__FILE__", line: %d, "
                "conf file: %s, expect config: data_path",
                __LINE__, filename);
        return ENOENT;
    }
    if (!fileExists(data_path)) {
        logError("file: "__FILE__", line: %d, "
                "data_path %s not exist",
                __LINE__, data_path);
        return ENOENT;
    }
    snprintf(g_server_vars.data_path, sizeof(g_server_vars.data_path),
            "%s", data_path);
    chopPath(g_server_vars.data_path);

    g_server_vars.question_index_hashtable_buckets = iniGetIntValue(NULL,
            "question_index_hashtable_buckets", &ini_context, 102400);
    if (g_server_vars.question_index_hashtable_buckets <= 0) {
        g_server_vars.question_index_hashtable_buckets = 102400;
    }

    g_server_vars.keyword_trie_top_hashtable_buckets = iniGetIntValue(NULL,
            "keyword_trie_top_hashtable_buckets", &ini_context, 10240);
    if (g_server_vars.keyword_trie_top_hashtable_buckets <= 0) {
        g_server_vars.keyword_trie_top_hashtable_buckets = 10240;
    }

    iniFreeContext(&ini_context);

    result = kengine_load_data(&total_file_count);

    sprintf(config_str, "data_path=%s, question_index_hashtable_buckets=%d, "
            "keyword_trie_top_hashtable_buckets=%d, kbase file count: %d",
            g_server_vars.data_path, g_server_vars.question_index_hashtable_buckets,
            g_server_vars.keyword_trie_top_hashtable_buckets, total_file_count);
    sf_log_config_ex(config_str);

    return result;
}
