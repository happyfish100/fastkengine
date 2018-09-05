//keyword_iterator.h

#ifndef _KEYWORD_ITERATOR_H
#define _KEYWORD_ITERATOR_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "fastcommon/common_define.h"

#define MAX_KEYWORDS_COUNT      5

typedef struct keyword_array {
    string_t keywords[MAX_KEYWORDS_COUNT];
    int count;
} KeywordArray;

typedef struct keyword_iterator_group {
    string_t keywords[MAX_KEYWORDS_COUNT];
    int count;
    int index;
} KeywordIteratorGroup;

typedef struct keyword_iterator_context {
    KeywordIteratorGroup groups[MAX_KEYWORDS_COUNT];
    int count;
    int index;
} KeywordIteratorContext;

#ifdef __cplusplus
extern "C" {
#endif

    int keyword_iterator_next(KeywordIteratorContext *context,
            KeywordArray *array);

#ifdef __cplusplus
}
#endif

#endif

