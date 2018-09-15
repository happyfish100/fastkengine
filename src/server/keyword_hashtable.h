//keyword_hashtable.h

#ifndef _KEYWORD_HASHTABLE_H
#define _KEYWORD_HASHTABLE_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "fastcommon/common_define.h"
#include "fastcommon/fast_mblock.h"
#include "fastcommon/fast_mpool.h"
#include "keyword_types.h"
#include "keyword_iterator.h"

typedef struct similar_keyword_input  {
    char **lines;
    int count;
    char seperator;
} SimilarKeywordsInput;

struct keyword_hashtable;

typedef struct keyword_hash_entry {
    string_t ch;
    string_t keyword;
    string_t similar;
    struct keyword_hashtable *children;
    struct keyword_hash_entry *next;
} KeywordHashEntry;

typedef struct keyword_hashtable {
    struct keyword_hash_entry **buckets;
    int capacity;
} KeywordHashtable;

typedef struct keyword_hashtable_context {
    KeywordHashtable *top;
    int top_capacity;
    int max_chinese_chars;
    struct fast_mblock_man htable_allocator;
    struct fast_mblock_man hentry_allocator;
    struct fast_mpool_man  string_allocator;
} KeywordHashtableContext;

#ifdef __cplusplus
extern "C" {
#endif

    int keyword_hashtable_init(KeywordHashtableContext *context, const int capacity,
            const SimilarKeywordsInput *similars);

    KeywordHashEntry *keyword_hashtable_find(KeywordHashtableContext *context,
            const string_t *keyword);

    KeywordHashEntry *keyword_hashtable_find_ex(KeywordHashtableContext *context,
            const string_t *chs, const int count);

    int keyword_hashtable_add_keywords(KeywordHashtableContext *context,
            const KeywordArray *keywords);

    void keyword_hashtable_destroy(KeywordHashtableContext *context);

#ifdef __cplusplus
}
#endif

#endif

