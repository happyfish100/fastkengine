#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>
#include "fastcommon/shared_func.h"
#include "fastcommon/pthread_func.h"
#include "fastcommon/process_ctrl.h"
#include "fastcommon/logger.h"
#include "fastcommon/sockopt.h"
#include "fastcommon/sched_thread.h"
#include "sf/sf_global.h"
#include "sf/sf_nio.h"
#include "sf/sf_service.h"
#include "sf/sf_util.h"
#include "wordsegment.h"
#include "similar_words.h"
//#include "common/fcfg_proto.h"
//#include "common/fcfg_types.h"

static bool daemon_mode = true;
static int setup_server_env(const char *config_filename);

static int test_segment();
static int test_similar_words();

int main(int argc, char *argv[])
{
    char *config_filename;
    char *action;
    char g_pid_filename[MAX_PATH_SIZE];
    pthread_t schedule_tid;
    int wait_count;
    bool stop;
    int r;
    failvars;

    stop = false;
    if (argc < 2) {
        sf_usage(argv[0]);
        return 1;
    }
    config_filename = argv[1];
    log_init2();

    r = get_base_path_from_conf_file(config_filename, g_sf_global_vars.base_path,
                                     sizeof(g_sf_global_vars.base_path));
    gofailif(r, "base path error");

    snprintf(g_pid_filename, sizeof(g_pid_filename), 
             "%s/fastkengined.pid", g_sf_global_vars.base_path);

    sf_parse_daemon_mode_and_action(argc, argv, &daemon_mode, &action);
    r = process_action(g_pid_filename, action, &stop);
    if (r == EINVAL) {
        sf_usage(argv[0]);
        log_destroy();
        return 1;
    }
    gofailif(r, "process arg error");

    if (stop) {
        log_destroy();
        return 0;
    }

    srand(time(NULL));
    rand();

    r = test_similar_words();
    r = test_segment();
    return r;

    sched_set_delay_params(300, 1024);
    r = setup_server_env(config_filename);
    gofailif(r,"");

    r = sf_startup_schedule(&schedule_tid);
    gofailif(r,"");

    r = sf_socket_server();
    gofailif(r, "socket server error");
    r = write_to_pid_file(g_pid_filename);
    gofailif(r, "write pid error");

    /*
    r = fcfg_server_handler_init();
    gofailif(r,"server handler init error");

    fcfg_proto_init();

    r = sf_service_init(fcfg_server_alloc_thread_extra_data,
            fcfg_server_thread_loop,
            NULL, fcfg_proto_set_body_length, fcfg_server_deal_task,
            fcfg_server_task_finish_cleanup, fcfg_server_recv_timeout_callback,
            100, sizeof(FCFGProtoHeader), sizeof(FCFGServerTaskArg));
    gofailif(r,"service init error");
    sf_set_remove_from_ready_list(false);
    */

    sf_accept_loop();
    if (g_schedule_flag) {
        pthread_kill(schedule_tid, SIGINT);
    }
    wait_count = 0;
    while ((g_worker_thread_count != 0) || g_schedule_flag) {
        usleep(10000);
        if (++wait_count > 1000) {
            lwarning("waiting timeout, exit!");
            break;
        }
    }

    sf_service_destroy();
    delete_pid_file(g_pid_filename);
    logInfo("file: "__FILE__", line: %d, "
            "program exit normally.\n", __LINE__);
    log_destroy();
    return 0;

FAIL_:
    logfail();
    lcrit("program exit abnomally");
    log_destroy();
    return eres;
}

static int setup_server_env(const char *config_filename)
{
    int result;

    sf_set_current_time();

    /*
    result = fcfg_server_load_config(config_filename);
    if (result != 0) {
        fprintf(stderr, "load from conf file %s fail, "
                "erro no: %d, error info: %s",
                config_filename, result, strerror(result));
        return result;
    }
    */

    if (daemon_mode) {
        daemon_init(false);
    }
    umask(0);

    result = sf_setup_signal_handler();

    log_set_cache(true);
    return result;
}

static int test_segment()
{
    char *buff;
    int64_t file_size;
    int result;
    int row_count;
    int i;
    char **rows;
    string_t *keywords;
    WordSegmentContext context;
    string_t input;
    WordSegmentArray output;
    int index;
    const char *filename = "/Users/yuqing/Devel/fastkengine/conf/keywords.txt";

    if ((result=getFileContent(filename, &buff, &file_size)) != 0) {
        return result;
    }

    rows = split(buff, '\n', 0, &row_count);
    keywords = (string_t *)malloc(sizeof(string_t) * row_count);
    for (i=0; i<row_count; i++) {
        keywords[i].str = rows[i];
        keywords[i].len = strlen(rows[i]);
    }

    result = word_segment_init(&context, 1024,
            keywords, row_count);

    index = (int)((int64_t)rand() * (row_count - 1) / (int64_t)RAND_MAX);
    input = keywords[index];

    input.str = "查 找 文 件 列  表";
    input.len = strlen(input.str);

    logInfo("row_count: %d, index: %d, %.*s", row_count, index, input.len, input.str);
    word_segment_split(&context, &input, &output);

    freeSplit(rows);
    word_segment_free_result(&output);

    return result;
}

static int test_similar_words()
{
    char *buff;
    int64_t file_size;
    int result;
    int row_count;
    int col_count;
    int row_index;
    int col_index;
    char **lines;
    char **cols;
    char *line;
    string_t keyword;
    const string_t *similar;
    SimilarWordsContext context;
    const char *filename = "/Users/yuqing/Devel/fastkengine/conf/similars.txt";

    if ((result=getFileContent(filename, &buff, &file_size)) != 0) {
        return result;
    }

    lines = split(buff, '\n', 0, &row_count);

    row_index = (int)((int64_t)rand() * (row_count - 1) / (int64_t)RAND_MAX);
    line = strdup(lines[row_index]);

    cols = split(line, ' ', 0,  &col_count); 
    col_index = (int)((int64_t)rand() * col_count / (int64_t)RAND_MAX);
    FC_SET_STRING(keyword, cols[col_index]);

    if ((result=similar_words_init(&context, 10240, lines, row_count - 1, ' ')) != 0) {
        return result;
    }

    similar = similar_words_find(&context, &keyword);
    logInfo("row_count: %d, row_index: %d, col_index: %d, "
            "keyword: %.*s", row_count, row_index, col_index,
            keyword.len, keyword.str);

    if (similar != NULL) {
        logInfo("similar: %.*s", similar->len, similar->str);
    }

    similar_words_destroy(&context);
    return 0;
}
