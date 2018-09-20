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
#include "question_index.h"
#include "server_global.h"
#include "qa_reader.h"
#include "qa_loader.h"
#include "question_search.h"
#include "common/fken_proto.h"
#include "server_handler.h"

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

    sched_set_delay_params(300, 1024);
    r = setup_server_env(config_filename);
    gofailif(r,"");


    r = test_segment();

    r = sf_startup_schedule(&schedule_tid);
    gofailif(r,"");

    r = sf_socket_server();
    gofailif(r, "socket server error");
    r = write_to_pid_file(g_pid_filename);
    gofailif(r, "write pid error");

    r = server_handler_init();
    gofailif(r,"server handler init error");

    fken_proto_init();

    r = sf_service_init(NULL, NULL, NULL, fken_proto_set_body_length,
            fken_server_deal_task, sf_task_finish_clean_up, NULL,
            100, sizeof(FKENProtoHeader), 0);
    gofailif(r,"service init error");
    sf_set_remove_from_ready_list(false);

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

    result = kengine_load_config_and_data(config_filename);
    if (result != 0) {
        fprintf(stderr, "load from conf file %s fail, "
                "erro no: %d, error info: %s",
                config_filename, result, strerror(result));
        return result;
    }

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
    int result;
    int i;
    string_t question;
    key_value_pair_t kv_pairs[FKEN_MAX_CONDITION_COUNT];
    AnswerConditionArray conditions;
    QASearchResultArray results;

    question.str = "查 找 文 件 列  表";
    question.str = "生成 core-dump";
    question.str = "core   dump设置生成 ";
    //question.str = "文件b超查找";
    //question.str = "中华 人民 共和国 中华 万岁";
    question.len = strlen(question.str);

    conditions.kv_pairs = kv_pairs;
    FC_SET_STRING(conditions.kv_pairs[0].key, "uname");
    FC_SET_STRING(conditions.kv_pairs[0].value, "Linux");
    conditions.count = 1;
    if ((result=question_search(&question, &conditions, &results)) != 0) {
        return result;
    }

    printf("answer count: %d\n", results.count);
    for (i=0; i<results.count; i++) {
        printf("answer[%d] START ###########\n", i + 1);
        printf("%.*s\n\n", FC_PRINTF_STAR_STRING_PARAMS(*(results.entries[i].answer)));
        printf("answer[%d] END ###########\n\n", i + 1);
    }

    return result;
}
