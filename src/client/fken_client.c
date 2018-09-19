#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/poll.h>
#include "fastcommon/shared_func.h"
#include "fastcommon/sockopt.h"
#include "fastcommon/logger.h"
#include "sf/sf_func.h"
#include "sf/sf_util.h"
#include "common/fken_proto.h"
#include "fken_client.h"

static int client_load_from_conf_file(FKenClient* client, const char *filename)
{
	IniContext ini_context;
	int result;

	memset(&ini_context, 0, sizeof(IniContext));
	if ((result=iniLoadFromFile(filename, &ini_context)) != 0) {
		logError("file: "__FILE__", line: %d, "
			"load conf file \"%s\" fail, ret code: %d",
			__LINE__, filename, result);
		return result;
	}

	do {
		client->network_timeout = iniGetIntValue(NULL, "network_timeout",
				&ini_context, DEFAULT_NETWORK_TIMEOUT);
		if (client->network_timeout <= 0) {
			client->network_timeout = DEFAULT_NETWORK_TIMEOUT;
		}
	
		client->connect_timeout = iniGetIntValue(NULL, "connect_timeout",
				&ini_context, DEFAULT_CONNECT_TIMEOUT);
		if (client->connect_timeout <= 0) {
			client->connect_timeout = DEFAULT_CONNECT_TIMEOUT;
		}

        if ((result=conn_pool_load_server_info(&ini_context, filename,
                        "server", &client->conn,
                        FKEN_SERVER_DEFAULT_INNER_PORT)) != 0)
        {
            break;
        }

        logDebug("FastKEngine connect_timeout=%ds, "
			"network_timeout=%ds, "
			"server=%s:%d",
			client->connect_timeout,
			client->network_timeout, 
            client->conn.ip_addr, client->conn.port);

	} while (0);

	iniFreeContext(&ini_context);
	return result;
}

int fken_client_init(FKenClient *client, const char *config_filename)
{
    int result;
    if (client == NULL) {
        logError("file:%s, line:%d client is null", __FILE__, __LINE__);
        return EINVAL;
    }

    fken_proto_init();
    srand(time(NULL));
    result = client_load_from_conf_file(client, config_filename);
    if (result != 0) {
        logError("file: %s, line: %d load config file fail, "
                "error: %s", __FILE__, __LINE__, strerror(result));
        return result;
    }

    result = conn_pool_connect_server(&client->conn,
            client->connect_timeout);
    return result;
}

int fken_client_destroy(FKenClient* client)
{
    if (client->conn.sock >= 0) {
        conn_pool_disconnect_server(&client->conn);
    }

    return 0;
}
