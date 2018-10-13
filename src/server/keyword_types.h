//keyword_types.h

#ifndef _KEYWORD_TYPES_H
#define _KEYWORD_TYPES_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "fastcommon/common_define.h"
#include "common/fken_types.h"

#define MAX_KEYWORDS_COUNT    5
#define MAX_KEYWORDS_ROWS    (4 * MAX_KEYWORDS_COUNT * MAX_KEYWORDS_COUNT)

#define CONDITION_OPERATOR_EQ 1
#define CONDITION_OPERATOR_IN 2

typedef struct keyword_array {
    string_t keywords[MAX_KEYWORDS_COUNT];
    int count;
} KeywordArray;

typedef struct keyword_records {
    KeywordArray rows[MAX_KEYWORDS_ROWS];
    int count;
} KeywordRecords;

typedef struct question_entry {
    KeywordArray karray;
    string_t q;   //multi keywords splited by seperator
} QuestionEntry;

typedef struct condition_entry {
    int op_type;
    string_t key;
    string_array_t values;
} ConditionEntry;

typedef struct condition_array {
    ConditionEntry *kv_pairs;
    int count;
} ConditionArray;

typedef struct condition_answer_entry {
    ConditionArray conditions;
    struct {
        string_t origin;
        string_t for_html;
    } answer;
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
    QAEntry entries[FKEN_MAX_ANSWER_COUNT];
    int count;    //entry count
    int matched_count;
} QAArray;

typedef struct qa_search_result_entry {
    int64_t id;
    QuestionEntry *question;
    string_t *answer;
} QASearchResultEntry;

typedef struct qa_search_result_array {
    QASearchResultEntry entries[FKEN_MAX_ANSWER_COUNT];
    int count;    //entry count
    int scan_count;
    int matched_count;
} QASearchResultArray;

#endif
