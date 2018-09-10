//keyword_iterator.h

#ifndef _KEYWORD_ITERATOR_H
#define _KEYWORD_ITERATOR_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "fastcommon/common_define.h"
#include "keyword_types.h"

typedef struct combine_keyword_info {
    struct {
        int start;
        int end;
    } offset;

    KeywordArray karray;
} CombineKeywordInfo;

typedef struct combo_keyword_group {
    CombineKeywordInfo rows[MAX_KEYWORDS_ROWS];
    int count;
} ComboKeywordGroup;

typedef struct keyword_iterator {
    ComboKeywordGroup groups[MAX_KEYWORDS_COUNT];
    int count;
} KeywordIterator;

#ifdef __cplusplus
extern "C" {
#endif

    bool combo_keyword_is_overlapp(const CombineKeywordInfo *key1,
            const CombineKeywordInfo *key2);

    void combo_keywords_append(CombineKeywordInfo *dest,
            const CombineKeywordInfo *append);

    void keyword_iterator_expand(KeywordIterator *iterator,
            ComboKeywordGroup *result);

#ifdef __cplusplus
}
#endif

#endif

