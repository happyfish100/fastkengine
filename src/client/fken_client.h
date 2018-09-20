#ifndef _FKEN_CLIENT_H_
#define _FKEN_CLIENT_H_

#include "fastcommon/connection_pool.h"
#include "common/fken_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define FKEN_DEFAULT_NETWORK_BUFFER_SIZE   (16 * 1024)

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
    string_t *answers, int *answer_count);

#ifdef __cplusplus
}
#endif

#endif

