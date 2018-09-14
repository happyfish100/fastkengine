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
#include "keyword_index.h"
#include "server_global.h"
#include "qa_reader.h"
#include "question_search.h"
//#include "common/fcfg_proto.h"
//#include "common/fcfg_types.h"

static bool daemon_mode = true;
static int setup_server_env(const char *config_filename);

static int test_segment();

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

    //r = test_similar_words();
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
    char *keywords_buff;
    char *similars_buff;
    int64_t file_size;
    int result;
    int row_count;
    int remain_count;
    int i;
    char **rows;
    KeywordArray keywords;
    SimilarKeywordsInput similars;
    QAReaderContext reader;
    string_t question;
    QAArray results;
    int index;
    const char *keywords_filename = "/Users/yuqing/Devel/fastkengine/conf/keywords.txt";
    const char *similars_filename = "/Users/yuqing/Devel/fastkengine/conf/similars.txt";

    if ((result=getFileContent(keywords_filename, &keywords_buff, &file_size)) != 0) {
        return result;
    }

    rows = split(keywords_buff, '\n', 0, &row_count);
    if ((result=getFileContent(similars_filename, &similars_buff, &file_size)) != 0) {
        return result;
    }

    similars.lines = split(similars_buff, '\n', 0, &similars.count);
    similars.seperator = ' ';

    init_combination_index_arrays();
    keyword_index_init(&g_server_vars.ki_context, 1024 * 1024);

    result = word_segment_init(&g_server_vars.ws_context, 102400, &similars);
    if (result != 0) {
        return result;
    }
    remain_count = row_count - 1;
    index = 0;
    while (remain_count > 0) {
        keywords.count = remain_count > MAX_KEYWORDS_COUNT ?
            MAX_KEYWORDS_COUNT : remain_count;
        remain_count -= keywords.count;
        for (i=0; i<keywords.count; i++) {
            FC_SET_STRING(keywords.keywords[i], rows[index]);
            index++;
        }
        result = word_segment_add_keywords(&g_server_vars.ws_context, &keywords);
        if (result != 0) {
            return result;
        }
    }

    result = qa_reader_init(&reader, &g_server_vars.ws_context.string_allocator,
            "../../conf/unix/file.ken");
    if (result != 0) {
        return result;
    }

    while (1) {
        QAReaderEntry entry;
        if (qa_reader_next(&reader, &entry) != 0) {
            break;
        }
    }
    return 0;

    index = (int)((int64_t)rand() * (row_count - 1) / (int64_t)RAND_MAX);
    question = keywords.keywords[index];

    //question.str = "查 找 文 件 列  表";
    question.str = "中华 人民 共和国 中华 万岁";
    question.len = strlen(question.str);

    logInfo("row_count: %d, index: %d, %.*s", row_count, index, question.len, question.str);

    if ((result=question_search(&question, &results)) != 0) {
        return result;
    }

    freeSplit(rows);
    return result;
}
