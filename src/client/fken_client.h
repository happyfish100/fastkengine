#ifndef _FKEN_CLIENT_H_
#define _FKEN_CLIENT_H_

#include "fastcommon/connection_pool.h"
#include "fken_types.h"

#define FKEN_DEFAULT_NETWORK_BUFFER_SIZE   (16 * 1024)

#ifdef __cplusplus
extern "C" {
#endif

typedef struct fken_answer_entry {
    int64_t id;
    string_t answer;
} FKenAnswerEntry;

typedef struct fken_answer_array {
    FKenAnswerEntry answers[FKEN_MAX_ANSWER_COUNT];
    int count;
} FKenAnswerArray;

typedef struct fken_client {
    ConnectionInfo conn;
    char           *buff;
    int            max_pkg_size;
    int            connect_timeout;
    int            network_timeout;
} FKenClient;

int fken_client_init(FKenClient *client, const char *config_filename);

void fken_client_destroy(FKenClient *client);

int fken_client_question_search(FKenClient *client, const string_t *question,
    const key_value_pair_t *conditions, const int condition_count,
    FKenAnswerArray *answer_array);

#ifdef __cplusplus
}
#endif

#endif

