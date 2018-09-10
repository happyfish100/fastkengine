#include <netdb.h>
#include <unistd.h>
#include <errno.h>
#include "fastcommon/logger.h"
#include "fastcommon/hash.h"
#include "fastcommon/shared_func.h"
#include "keyword_iterator.h"

bool combo_keyword_is_overlapp(const CombineKeywordInfo *key1,
        const CombineKeywordInfo *key2)
{
    if (key1->offset.start == key2->offset.start) {
        return true;
    } if (key1->offset.start < key2->offset.start) {
        return key1->offset.end > key2->offset.start;
    } else {
        return key2->offset.end > key1->offset.start;
    }
}

void combo_keywords_append(CombineKeywordInfo *dest,
        const CombineKeywordInfo *append)
{
    int i;
    if (append->offset.start < dest->offset.start) {
        dest->offset.start = append->offset.start;
    }
    if (append->offset.end > dest->offset.end) {
        dest->offset.end = append->offset.end;
    }

    for (i=0; i<append->karray.count; i++) {
        if (dest->karray.count >= MAX_KEYWORDS_COUNT) {
            logWarning("file: "__FILE__", line: %d, "
                    "keywords exceeds %d",
                    __LINE__, MAX_KEYWORDS_COUNT);
            break;
        }
        dest->karray.keywords[dest->karray.count++] =
            append->karray.keywords[i];
    }
}

static void keyword_iterator_combine(ComboKeywordGroup *output,
        const ComboKeywordGroup *second)
{
    ComboKeywordGroup first;
    int i, k;

    first = *output;
    output->count = 0;
    for (i=0; i<first.count; i++) {
        for (k=0; k<second->count; k++) {
            if (!combo_keyword_is_overlapp(first.rows + i,
                        second->rows + k))
            {
                if (output->count == MAX_KEYWORDS_ROWS) {
                    logWarning("file: "__FILE__", line: %d, "
                            "too many keywords rows exceeds %d",
                            __LINE__, MAX_KEYWORDS_ROWS);
                    break;
                }

                output->rows[output->count] = first.rows[i];
                combo_keywords_append(output->rows + output->count,
                        second->rows + k);
                output->count++;
            }
        }
    }
}

void keyword_iterator_expand(KeywordIterator *iterator,
        ComboKeywordGroup *result)
{
    ComboKeywordGroup *group;
    int i;

    if (iterator->count == 0) {
        result->count = 0;
        return;
    }

    group = iterator->groups;
    result->count = group->count;
    for (i=0; i<group->count; i++) {
        result->rows[i] = group->rows[i];
    }

    for (i=1; i<iterator->count; i++) {
        keyword_iterator_combine(result, iterator->groups + i);
    }
}
