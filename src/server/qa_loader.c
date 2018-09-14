#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include "fastcommon/shared_func.h"
#include "fastcommon/logger.h"
#include "fastcommon/fast_buffer.h"
#include "server_global.h"
#include "qa_reader.h"
#include "qa_loader.h"


static int load_question_answers(QAReaderContext *reader)
{
    int result;
    QAReaderEntry entry;

    while (1) {
        if ((result=qa_reader_next(reader, &entry)) != 0) {
            break;
        }

        keyword_records_unique(&entry.questions);
    }

    return result;
}
 
int qa_loader_init(const char **filenames, const int count)
{
    int result;
    QAReaderContext reader;
    FastBuffer buffer;
    const char **pp;
    const char **end;

    if ((result=fast_buffer_init_ex(&buffer, 4096)) != 0) {
        return result;
    }

    end = filenames + count;
    for (pp=filenames; pp<end; pp++) {
        result = qa_reader_init(&reader, &g_server_vars.ws_context.
                string_allocator, &buffer, *pp);
        if (result != 0) {
            break;
        }

        result = load_question_answers(&reader);
        if (result == ENOENT) {
            result = 0;
        }
        qa_reader_destroy(&reader);

        if (result != 0) {
            break;
        }
   }

    fast_buffer_destroy(&buffer);
    return result;
}
