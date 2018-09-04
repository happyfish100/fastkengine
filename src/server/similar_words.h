//similar_words.h

#ifndef _SIMILAR_WORDS_H
#define _SIMILAR_WORDS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "fastcommon/common_define.h"
#include "fastcommon/fast_mblock.h"
#include "fastcommon/fast_mpool.h"

typedef struct similar_words_hash_entry {
    string_t word;
    string_t similar;
    struct similar_words_hash_entry *next;
} SimilarWordsHashEntry;

typedef struct similar_words_hash_table {
    struct similar_words_hash_entry **buckets;
    int capacity;
} SimilarWordsHashTable;

typedef struct similar_words_context {
    SimilarWordsHashTable htable;
    struct fast_mblock_man hentry_allocator;
    struct fast_mpool_man  string_allocator;
} SimilarWordsContext;

#ifdef __cplusplus
extern "C" {
#endif

    int similar_words_init(SimilarWordsContext *context, const int capacity,
            char **lines, const int count, const char seperator);

    void similar_words_destroy(SimilarWordsContext *context);

    const string_t *similar_words_find(SimilarWordsContext *context,
            const string_t *keyword);

#ifdef __cplusplus
}
#endif

#endif

