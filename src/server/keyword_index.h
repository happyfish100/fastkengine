//keyword_index.h

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

typedef struct keyword_index_hash_entry {
    QuestionEntry question;
    AnswerEntry *answer;
    struct keyword_index_hash_entry *next;
} KeywordIndexHashEntry;

typedef struct keyword_index_hash_table {
    struct keyword_index_hash_entry **buckets;
    int capacity;
} KeywordIndexHashTable;

typedef struct keyword_index_context {
    KeywordIndexHashTable htable;
    struct fast_mblock_man hentry_allocator;
    struct fast_mpool_man  string_allocator;
} KeywordIndexContext;

#ifdef __cplusplus
extern "C" {
#endif

    int keyword_index_init(KeywordIndexContext *context, const int capacity);

    void keyword_index_destroy(KeywordIndexContext *context);

    int keyword_index_add(KeywordIndexContext *context,
            const KeywordArray *keywords, AnswerEntry *answer);

    int keyword_index_find(KeywordIndexContext *context,
            const KeywordArray *keywords, QAEntry *qa);

    int keyword_index_key_length(const KeywordArray *keywords);

#ifdef __cplusplus
}
#endif

#endif
