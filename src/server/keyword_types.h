//keyword_types.h

#ifndef _KEYWORD_TYPES_H
#define _KEYWORD_TYPES_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "fastcommon/common_define.h"

#define MAX_KEYWORDS_COUNT    5
#define MAX_KEYWORDS_ROWS  (MAX_KEYWORDS_COUNT * MAX_KEYWORDS_COUNT)

#define MAX_ANSWER_COUNT      5

typedef struct keyword_array {
    string_t keywords[MAX_KEYWORDS_COUNT];
    int count;
} KeywordArray;

typedef struct keyword_records {
    KeywordArray rows[MAX_KEYWORDS_ROWS];
    int count;
} KeywordRecords;

typedef struct question_entry {
    string_t q;   //multi keywords splited by seperator
    int kcount;   //keywords count
} QuestionEntry;

typedef struct condition_answer_entry {
    struct {
        key_value_pair_t *kv_pairs;
        int count;
    } conditions;
    string_t answer;
} ConditionAnswerEntry;

typedef struct condition_answer_array {
    ConditionAnswerEntry *entries;  //[0] for no condition answer
    int count;
} ConditionAnswerArray;

typedef struct answer_entry {
    ConditionAnswerArray condition_answers;
    int64_t id;
} AnswerEntry;

typedef struct question_answer_entry {
    QuestionEntry *question;
    AnswerEntry *answer;
} QAEntry;

typedef struct question_answer_array {
    QAEntry entries[MAX_ANSWER_COUNT];
    int count;    //entry count
    int match_count;
} QAArray;

#endif
