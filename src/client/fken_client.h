#ifndef _MC_CLIENT_H_
#define _MC_CLIENT_H_
#include "fastcommon/connection_pool.h"
#include "sf/sf_types.h"
#ifdef __cplusplus
extern "C" {
#endif

typedef struct fken_client {
    ConnectionInfo conn;
    int            connect_timeout;
    int            network_timeout;
} FKenClient;

int fken_client_init(FKenClient *client, const char *config_filename);

int fken_client_destroy(FKenClient* client);

#ifdef __cplusplus
}
#endif

#endif

