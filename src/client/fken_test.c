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
    key_value_pair_t vars[FKEN_MAX_CONDITION_COUNT];
    int var_count;
    int answer_format;
    int result;
    int i;

    if (argc < 3) {
        fprintf(stderr, "Usage: %s <config_filename> <question> [format]\n"
                "\t format: text or html, default is text\n\n", argv[0]);
        return EINVAL;
    }
    config_filename = argv[1];
    FC_SET_STRING(question, argv[2]);
    if (argc > 3) {
        if (strcasecmp(argv[3], "html") == 0) {
            answer_format = FKEN_ANSWER_FORMAT_HTML;
        } else {
            answer_format = FKEN_ANSWER_FORMAT_TEXT;
        }
    } else {
        answer_format = FKEN_ANSWER_FORMAT_TEXT;
    }

    log_init();
    if ((result=fken_client_init(&client, config_filename)) != 0)  {
        return result;
    }

    FC_SET_STRING(vars[0].key, "uname");
    FC_SET_STRING(vars[0].value, "Darwin");
    FC_SET_STRING(vars[1].key, "osname");
    FC_SET_STRING(vars[1].value, "FreeBSD");
    var_count = 2;
    if ((result=fken_client_question_search(&client, &question,
                    vars, var_count, answer_format, &answer_array)) != 0)
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
