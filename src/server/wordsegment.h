//wordsegment.h

#ifndef _WORD_SEGMENT_H
#define _WORD_SEGMENT_H

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

typedef struct word_segment_hash_entry {
    string_t keyword;
    string_t similar;
    struct word_segment_hash_entry *next;
} WordSegmentHashEntry;

typedef struct word_segment_hash_table {
    struct word_segment_hash_entry **buckets;
    int capacity;
} WordSegmentHashTable;

typedef struct word_segment_context {
    WordSegmentHashTable htable;
    int max_chinese_chars;
    struct fast_mblock_man hentry_allocator;
    struct fast_mpool_man  string_allocator;
} WordSegmentContext;

typedef struct word_segment_array {
    KeywordRecords results;

    char buff[256];   //for internal use
    string_t holder;  //for internal use
} WordSegmentArray;

#ifdef __cplusplus
extern "C" {
#endif

    int word_segment_init(WordSegmentContext *context, const int capacity,
            const SimilarKeywordsInput *similars);

    int word_segment_add_keywords(WordSegmentContext *context,
            const KeywordArray *keywords);

    void word_segment_destroy(WordSegmentContext *context);

    void word_segment_normalize(const string_t *input, string_t *output);

    void keywords_unique(KeywordArray *karray);

    int word_segment_split(WordSegmentContext *context, const string_t *input,
            WordSegmentArray *output);

    void word_segment_free_result(WordSegmentArray *array);

#ifdef __cplusplus
}
#endif

#endif

