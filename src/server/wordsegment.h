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

typedef struct word_segment_array {
    KeywordRecords results;

    char buff[256];   //for internal use
    string_t holder;  //for internal use
} WordSegmentArray;

#ifdef __cplusplus
extern "C" {
#endif

    int word_segment_next_word(const char **pp, const char *end,
            string_t *ch, bool *is_chinese);

    void word_segment_normalize(const string_t *input, string_t *output);

    void keywords_unique(KeywordArray *karray);

    void keyword_records_unique(KeywordRecords *results);

    int word_segment_split(const string_t *input, WordSegmentArray *output);

    void word_segment_free_result(WordSegmentArray *array);

#ifdef __cplusplus
}
#endif

#endif

