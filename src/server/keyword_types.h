//keyword_types.h

#ifndef _KEYWORD_TYPES_H
#define _KEYWORD_TYPES_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "fastcommon/common_define.h"

#define MAX_KEYWORDS_COUNT      5
#define MAX_KEYWORDS_ROWS  (MAX_KEYWORDS_COUNT * MAX_KEYWORDS_COUNT)

typedef struct keyword_array {
    string_t keywords[MAX_KEYWORDS_COUNT];
    int count;
} KeywordArray;

typedef struct keyword_records {
    KeywordArray rows[MAX_KEYWORDS_ROWS];
    int count;
} KeywordRecords;

#endif
