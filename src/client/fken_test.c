#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "fastcommon/logger.h"
#include "fken_client.h"

int main(int argc, char *argv[])
{
    FKenClient client;
    const char *config_filename;
    string_t question;
    FKenAnswerArray answer_array;
    key_value_pair_t conditions[FKEN_MAX_CONDITION_COUNT];
    int condition_count;
    int result;
    int i;

    if (argc < 3) {
        fprintf(stderr, "Usage: %s <config_filename> <question>\n",
                argv[0]);
        return EINVAL;
    }
    config_filename = argv[1];
    FC_SET_STRING(question, argv[2]);

    log_init();
    if ((result=fken_client_init(&client, config_filename)) != 0)  {
        return result;
    }

    condition_count = 0;
    if ((result=fken_client_question_search(&client, &question,
                    conditions, condition_count, &answer_array)) != 0)
    {
        printf("result: %d\n", result);
        return result;
    }

    printf("answer count: %d\n", answer_array.count);
    for (i=0; i<answer_array.count; i++) {
        printf("%d. answer========\n", i + 1);
        printf("id: %"PRId64"\n", answer_array.answers[i].id);
        printf("%.*s\n", FC_PRINTF_STAR_STRING_PARAMS(answer_array.answers[i].answer));
    }

    fken_client_destroy(&client);
    return 0;
}
