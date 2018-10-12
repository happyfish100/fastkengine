//question_index.h

#ifndef _KEYWORD_INDEX_H
#define _KEYWORD_INDEX_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "fastcommon/common_define.h"
#include "fastcommon/fast_mblock.h"
#include "fastcommon/fast_mpool.h"
#include "keyword_types.h"

typedef struct question_buffer {
    string_t question;
    char buff[256];   //for internal use
} QuestionBuffer;

typedef struct question_index_hash_entry {
    QuestionEntry question;
    AnswerEntry answer;
    struct question_index_hash_entry *next;
} KeywordIndexHashEntry;

typedef struct question_index_hash_table {
    struct question_index_hash_entry **buckets;
    int capacity;
} KeywordIndexHashTable;

typedef struct question_index_context {
    KeywordIndexHashTable htable;
    struct fast_mblock_man hentry_allocator;
    struct fast_mpool_man  string_allocator;
} KeywordIndexContext;

#ifdef __cplusplus
extern "C" {
#endif

    int question_index_init(KeywordIndexContext *context, const int capacity);

    void question_index_destroy(KeywordIndexContext *context);

    int question_index_adds(KeywordIndexContext *context,
            const KeywordRecords *records, AnswerEntry *answer);

    int question_index_find(KeywordIndexContext *context,
            const KeywordArray *keywords, QAEntry *qa);

    int question_index_key_length(const KeywordArray *keywords);

    static inline int question_index_count(KeywordIndexContext *context)
    {
        return context->hentry_allocator.info.element_used_count;
    }

#ifdef __cplusplus
}
#endif

#endif
