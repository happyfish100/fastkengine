#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include "fastcommon/common_define.h"
#include "fastcommon/shared_func.h"
#include "fastcommon/logger.h"
#include "server_global.h"
#include "qa_reader.h"

#define QA_TAG_MAX_ATTRIBUTES   FKEN_MAX_CONDITION_COUNT
#define QA_SHOW_CONTENT_SIZE    256
#define QA_MAX_ANSWER_ENTRIES   64

#define MAX_CONDITION_VALUES_COUNT  5

#define TAG_BASE_STR      "base"
#define TAG_QUESTION_STR  "question"
#define TAG_ANSWER_STR    "answer"

#define TAG_BASE_LEN      (sizeof(TAG_BASE_STR) - 1)
#define TAG_QUESTION_LEN  (sizeof(TAG_QUESTION_STR) - 1)
#define TAG_ANSWER_LEN    (sizeof(TAG_ANSWER_STR) - 1)

#define ATTRIBUTE_ID_STR   "id"
#define ATTRIBUTE_ID_LEN   (sizeof(ATTRIBUTE_ID_STR) - 1)

#define FUNC_IN_STR       "in"
#define FUNC_IN_LEN       (sizeof(FUNC_IN_STR) - 1)

typedef struct {
    string_t name;
    char *start;
    char *end;
    char *next;
} QATagInfo;

typedef struct {
    key_value_pair_t kv_pairs[QA_TAG_MAX_ATTRIBUTES];
    int count;
} QATagAttributeArray;

typedef struct {
    ConditionEntry kv_pairs[QA_TAG_MAX_ATTRIBUTES];
    string_t values[QA_TAG_MAX_ATTRIBUTES * MAX_CONDITION_VALUES_COUNT];
} QAConditionHolder;

#define QA_SHOW_CONTENT_LENGTH(len) \
    (len > QA_SHOW_CONTENT_SIZE ? QA_SHOW_CONTENT_SIZE : len)

static void qa_reader_set_tag_next(QAReaderContext *context, QATagInfo *tag)
{
    char *p;

    p = tag->end;
    while (p < context->end && (*p == ' ' || *p == '\t' || *p == '\r')) {
        p++;
    }
    if (p < context->end && *p == '\n') {
        p++;  //skip newline
        tag->next = p;
    } else {
        tag->next = tag->end;
    }
}

static int qa_reader_next_tag(QAReaderContext *context, QATagInfo *tag)
{
    char *p;

    tag->start = strstr(context->p, "[[");
    if (tag->start == NULL) {
        return ENOENT;
    }

    tag->name.str = tag->start + 2;
    tag->end = strstr(tag->name.str, "]]");
    if (tag->end == NULL) {
        logError("file: "__FILE__", line: %d, "
                "expect ]] in file: %s",
                __LINE__, context->filename);
        return EINVAL;
    }

    p = tag->name.str;
    while (p < tag->end && !(*p == ' ' || *p == '\t')) {
        p++;
    }

    tag->name.len = p - tag->name.str;
    tag->end += 2;   //skip ]]
    qa_reader_set_tag_next(context, tag);
    return 0;
}

static int get_next_expect_tag(QAReaderContext *context,
        const char *tag_name, const int tag_len, QATagInfo *tag)
{
    char mark[64];
    char *p;

    p = context->p;
    sprintf(mark, "[[%s", tag_name);
    while (p < context->end) {
        tag->start = strstr(p, mark);
        if (tag->start == NULL) {
            return ENOENT;
        }

        tag->name.str = tag->start + 2;
        p = tag->name.str + tag_len;
        if (*p == ' ' || *p == '\t' || *p == ']') {
            break;
        }
    }
    if (p == context->end) {
        return ENOENT;
    }

    tag->end = strstr(tag->name.str, "]]");
    if (tag->end == NULL) {
        logError("file: "__FILE__", line: %d, "
                "expect ]] in file: %s",
                __LINE__, context->filename);
        return EINVAL;
    }

    tag->name.len = tag_len;
    tag->end += 2;
    qa_reader_set_tag_next(context, tag);
    return 0;
}

static int get_first_end_tag(QAReaderContext *context,
        const char *tag_name1, const int tag_len1,
        const char *tag_name2, const int tag_len2,
        QATagInfo *tag)
{
    QATagInfo tag1, tag2;
    int r1, r2;

    r1 = get_next_expect_tag(context, tag_name1, tag_len1, &tag1);
    r2 = get_next_expect_tag(context, tag_name2, tag_len2, &tag2);
    if (r1 == 0) {
        if (r2 == 0) {
            *tag = tag1.start < tag2.start ? tag1 : tag2;
        } else {
            *tag = tag1;
        }
        return 0;
    } else if (r2 == 0) {
        *tag = tag2;
        return 0;
    }

    return r1;
}

static int qa_reader_parse_attribute_string(QAReaderContext *context,
        char **pp, char *end, const char stop, string_t *out)
{
    char *p;
    char *start;
    char quote_ch;

    p = start = *pp;
    quote_ch = *p;
    if (quote_ch == '"' || quote_ch == '\'') {
        out->str = ++p;
        while (p < end && *p != quote_ch) {
            p++;
        }
        if (p == end) {
            logError("file: "__FILE__", line: %d, "
                    "expect %c in file: %s, from: %.*s",
                    __LINE__, quote_ch, context->filename,
                    QA_SHOW_CONTENT_LENGTH((int)((end + 2) - start)), start);
            return ENOENT;
        }
        out->len = p - out->str;
        p++; //skip quote char
    } else {
        out->str = p;
        while (p < end && !(*p == ' ' || *p == '\t' || *p == stop)) {
            p++;
        }
        out->len = p - out->str;
    }

    *pp = p;
    return 0;
}

#define SKIP_SPACES(p, end) \
    do {  \
        while (p < end && (*p == ' ' || *p == '\t')) { \
            p++;   \
        }  \
    } while (0)

static int qa_reader_parse_attributes(QAReaderContext *context, QATagInfo *tag,
        QATagAttributeArray *attributes)
{
    int result;
    char *p;
    char *end;
    key_value_pair_t *kv;

    attributes->count = 0;
    p = tag->name.str + tag->name.len;
    end = tag->end - 2;
    while (p < end) {
        SKIP_SPACES(p, end);
        if (p == end) {
            break;
        }

        if (attributes->count == QA_TAG_MAX_ATTRIBUTES) {
            logWarning("file: "__FILE__", line: %d, "
                    "too many attributes in file: %s, tag: %.*s",
                    __LINE__, context->filename, QA_SHOW_CONTENT_LENGTH(
                        (int)(tag->end - tag->start)), tag->start);
            return ENOSPC;
        }

        kv = attributes->kv_pairs + attributes->count;
        if ((result=qa_reader_parse_attribute_string(context, &p, end,
                        '=', &kv->key)) != 0)
        {
            return result;
        }

        SKIP_SPACES(p, end);
        if (p == end || *p != '=') {
            kv->value.str = NULL;
            kv->value.len = 0;
            attributes->count++;
            continue;
        }

        p++; //skip =
        SKIP_SPACES(p, end);
        if ((result=qa_reader_parse_attribute_string(context, &p, end,
                        '\0', &kv->value)) != 0)
        {
            return result;
        }
        attributes->count++;
    }

    return 0;
}

static const string_t *qa_reader_get_attribute(const QATagAttributeArray
        *attributes, const char *name, const int len)
{
    const key_value_pair_t *p;
    const key_value_pair_t *end;

    end = attributes->kv_pairs + attributes->count;
    for (p=attributes->kv_pairs; p<end; p++) {
        if (fc_string_equal2(&p->key, name, len)) {
            return &p->value;
        }
    }

    return NULL;
}

static int qa_reader_strtol(const string_t *in, int64_t *n)
{
    char *endptr;
    char buff[32];

    if (in->len == 0 || in->len >= sizeof(buff)) {
        *n = 0;
        return EINVAL;
    }
    memcpy(buff, in->str, in->len);
    *(buff + in->len) = '\0';

    *n = strtoll(buff, &endptr, 10);
    if (endptr != NULL && *endptr != '\0') {
        return EINVAL;
    }
    return 0;
}

static int qa_reader_get_attribute_id(QAReaderContext *context, QATagInfo *tag,
        int64_t *id)
{
    int result;
    QATagAttributeArray attributes;
    const string_t *str;

    if ((result=qa_reader_parse_attributes(context, tag, &attributes)) != 0) {
        *id = 0;
        return result;
    }

    str = qa_reader_get_attribute(&attributes, ATTRIBUTE_ID_STR,
            ATTRIBUTE_ID_LEN);
    if (str == NULL) {
        logWarning("file: "__FILE__", line: %d, "
                "no attribute %s of %.*s in file: %s, tag: %.*s",
                __LINE__, ATTRIBUTE_ID_STR,
                FC_PRINTF_STAR_STRING_PARAMS(tag->name),
                context->filename, QA_SHOW_CONTENT_LENGTH(
                    (int)(tag->end - tag->start)), tag->start);
        *id = 0;
        return ENOENT;
    }

    if ((result=qa_reader_strtol(str, id)) != 0) {
        logWarning("file: "__FILE__", line: %d, "
                "invalid id: %.*s in file: %s, tag: %.*s",
                __LINE__, FC_PRINTF_STAR_STRING_PARAMS(*str),
                context->filename, QA_SHOW_CONTENT_LENGTH(
                    (int)(tag->end - tag->start)), tag->start);
        return result;
    }

    return 0;
}

static int qa_reader_get_base_id(QAReaderContext *context)
{
    QATagInfo tag;

    if (qa_reader_next_tag(context, &tag) != 0) {
        context->base_id = 0;
        return 0;
    }

    if (!fc_string_equal2(&tag.name, TAG_BASE_STR, TAG_BASE_LEN)) {
        context->base_id = 0;
        return 0;
    }

    context->p = tag.end;   //skip base tag
    return qa_reader_get_attribute_id(context, &tag, &context->base_id);
}

int qa_reader_init(QAReaderContext *context, struct fast_mpool_man *mpool,
        FastBuffer *buffer, const char *filename)
{
    int result;
    int64_t file_size;

    context->filename = filename;
    if ((result=getFileContent(filename, &context->file_content.str,
                    &file_size)) != 0)
    {
        return result;
    }

    context->file_content.len = file_size;
    context->mpool = mpool;
    context->buffer = buffer;
    context->p = context->file_content.str;
    context->end = context->file_content.str + context->file_content.len;

    return qa_reader_get_base_id(context);
}

void qa_reader_destroy(QAReaderContext *context)
{
    if (context->file_content.str != NULL) {
        free(context->file_content.str);
        context->file_content.str = NULL;
    }
}

static int expand_combined_keywords(const string_t *input,
        string_t *keywords, const int max_cnt, int *count)
{
    char *p;
    char *end;
    string_t *keyword;

    keyword = keywords;
    end = input->str + input->len;
    p = input->str;
    while (p < end) {

        if (keyword - keywords >= max_cnt) {
            logWarning("file: "__FILE__", line: %d, "
                    "too many keywords exceeds %d, "
                    "combined keywords: %.*s",
                    __LINE__, max_cnt,
                    FC_PRINTF_STAR_STRING_PARAMS(*keywords));
            break;
        }

        keyword->str = p;
        p = memchr(p, '|', end - p);
        if (p != NULL) {
            keyword->len = p - keyword->str;
            p++; //skip |
        } else {
            keyword->len = end - keyword->str;
            p = end;
        }

        FC_STRING_TRIM(keyword);
        if (keyword->len == 0) {
            continue;
        }

        logInfo("combined keyword==== %.*s", FC_PRINTF_STAR_STRING_PARAMS(*keyword));
        keyword++;
    }

    *count = keyword - keywords;
    return *count > 0 ? 0 : ENOENT;
}

static int records_combine_keywords(KeywordRecords *records,
        const string_t *keywords, const int count)
{
    KeywordRecords temp;
    KeywordArray *p;
    KeywordArray *end;
    KeywordArray *dest;
    int i;

    temp.count = records->count;
    memcpy(temp.rows, records->rows, sizeof(KeywordArray) * records->count);

    records->count = 0;
    end = temp.rows + temp.count;
    for (p=temp.rows; p<end; p++) {
        if (p->count >= MAX_KEYWORDS_COUNT) {
            logWarning("file: "__FILE__", line: %d, "
                    "keywords exceeds %d",
                    __LINE__, MAX_KEYWORDS_COUNT);
            return ENOSPC;
        }

        for (i=0; i<count; i++) {
            if (records->count >= MAX_KEYWORDS_ROWS) {
                logWarning("file: "__FILE__", line: %d, "
                        "keyword rows exceeds %d",
                        __LINE__, MAX_KEYWORDS_ROWS);
                return ENOSPC;
            }

            dest = records->rows + records->count++;
            *dest = *p;
            dest->keywords[dest->count++] = keywords[i];
        }
    }

    return 0;
}

static int records_combine_records(KeywordRecords *records,
        const KeywordRecords *another)
{
    KeywordRecords temp;
    KeywordArray *p1;
    KeywordArray *end1;
    const KeywordArray *p2;
    const KeywordArray *end2;
    KeywordArray *dest;
    int result;

    temp.count = records->count;
    memcpy(temp.rows, records->rows, sizeof(KeywordArray) * records->count);

    end1 = temp.rows + temp.count;
    end2 = another->rows + another->count;
    for (p1=temp.rows; p1<end1; p1++) {
        if (p1->count >= MAX_KEYWORDS_COUNT) {
            logWarning("file: "__FILE__", line: %d, "
                    "keywords exceeds %d",
                    __LINE__, MAX_KEYWORDS_COUNT);
            return ENOSPC;
        }

        for (p2=another->rows; p2<end2; p2++) {
            if (records->count >= MAX_KEYWORDS_ROWS) {
                logWarning("file: "__FILE__", line: %d, "
                        "keyword rows exceeds %d",
                        __LINE__, MAX_KEYWORDS_ROWS);
                return ENOSPC;
            }

            dest = records->rows + records->count++;
            *dest = *p1;
            if ((result=keywords_append(dest, p2)) != 0) {
                return result;
            }
        }
    }

    return 0;
}

static int expand_question_keywords(QAReaderContext *context,
        const KeywordArray *karray, KeywordRecords *records)
{
    int result;
    KeywordArray single;
    KeywordArray multi;
    const string_t *current;
    const string_t *end;
    string_t keys[MAX_KEYWORDS_ROWS];
    int count;
    int start;
    int i;

    if (karray->count == 0) {
        records->count = 0;
        return ENOENT;
    }

    single.count = multi.count = 0;
    end = karray->keywords + karray->count;
    for (current=karray->keywords; current<end; current++) {
        if (memchr(current->str, '|', current->len) != NULL) {
            multi.keywords[multi.count++] = *current;
        } else {
            single.keywords[single.count++] = *current;
        }
    }

    if (single.count > 0) {
        start = 0;
        records->count = 1;
        records->rows[0] = single;
    } else {
        start = 1;
        result = expand_combined_keywords(multi.keywords + 0,
                keys, MAX_KEYWORDS_ROWS, &count);
        if (result != 0) {
            return result;
        }

        for (i=0; i<count; i++) {
            records->rows[i].count = 1;
            records->rows[i].keywords[0] = keys[i];
        }
        records->count = count;
    }

    for (i=start; i<multi.count; i++) {
        result = expand_combined_keywords(multi.keywords + i,
                keys, MAX_KEYWORDS_ROWS, &count);
        if (result != 0) {
            continue;
        }

        if ((result=records_combine_keywords(records, keys, count)) != 0) {
            return result;
        }
    }

    return 0;
}

static int parse_question_keywords(QAReaderContext *context,
        const string_t *keywords, KeywordRecords *records)
{
    char *p;
    char *end;
    string_t *current;
    KeywordArray karray;

    karray.count = 0;
    current = karray.keywords;
    end = keywords->str + keywords->len;
    p = keywords->str;
    while (p < end) {
        while (p < end && (*p == ' ' || *p == '\t')) {
            p++;
        }
        if (p == end) {
            break;
        }

        if (karray.count == MAX_KEYWORDS_COUNT) {
            logWarning("file: "__FILE__", line: %d, "
                    "too many keywords exceeds %d, question: %.*s",
                    __LINE__, MAX_KEYWORDS_COUNT,
                    FC_PRINTF_STAR_STRING_PARAMS(*keywords));
            break;
        }

        if (*p == '(') {
            current->str = ++p;
            while (p < end && *p != ')') {
                p++;
            }
            if (p == end) {
                logWarning("file: "__FILE__", line: %d, "
                        "expect ), question: %.*s", __LINE__,
                        FC_PRINTF_STAR_STRING_PARAMS(*keywords));
            }
        } else {
            current->str = p++;
            while (p < end && !(*p == ' ' || *p == '\t')) {
                p++;
            }
        }

        current->len = p - current->str;
        if (p < end) {
            p++;  //skip end char
        }

        if (current->len == 0) {
            logWarning("file: "__FILE__", line: %d, "
                    "empty keyword, question: %.*s", __LINE__,
                    FC_PRINTF_STAR_STRING_PARAMS(*keywords));
            continue;
        }

        current++;
        karray.count++;
    }

    /*
    logInfo("keywords count: %d", karray.count);
    for (current=karray.keywords; current<karray.keywords+karray.count; current++) {
        printf("%.*s ", FC_PRINTF_STAR_STRING_PARAMS(*current));
    }
    printf("\n");
    */

    return expand_question_keywords(context, &karray, records);
}


static void print_keyword_records(KeywordRecords *records)
{
    KeywordArray *p;
    KeywordArray *end;
    int i;

    printf("==========================\n");
    printf("row count: %d\n", records->count);
    end = records->rows + records->count;
    for (p=records->rows; p<end; p++) {
        for (i=0; i<p->count; i++) {
            printf("%.*s ", FC_PRINTF_STAR_STRING_PARAMS(p->keywords[i]));
        }
        printf("\n");
    }
    printf("==========================\n");
    printf("\n");
}

static int parse_a_question(QAReaderContext *context,
        const string_t *line, KeywordRecords *records)
{
    typedef struct {
        string_t s;
        KeywordRecords records;
    } KeywordStringRecords;

    KeywordStringRecords required;
    KeywordStringRecords optional;

    if (line->str[line->len - 1] == ']') {
        char *p;
        p = line->str + line->len - 1;
        while (p >= line->str && *p != '[') {
            p--;
        }
        if (p >= line->str) {  //found
            required.s.str = line->str;
            required.s.len = p - line->str;

            optional.s.str = p + 1;
            optional.s.len = line->len - required.s.len - 2;
        } else {
            required.s = *line;
            FC_SET_STRING_NULL(optional.s);
        }
    } else {
        required.s = *line;
        FC_SET_STRING_NULL(optional.s);
    }

    parse_question_keywords(context, &required.s, records);
    if (!FC_IS_NULL_STRING(&optional.s)) {
        parse_question_keywords(context, &optional.s, &optional.records);
        records_combine_records(records, &optional.records);
    }

    //print_keyword_records(records);
    return 0;
}

static int qa_reader_parse_question(QAReaderContext *context,
        const string_t *lines, QAReaderEntry *entry)
{
    char *p;
    char *end;
    string_t line;
    KeywordRecords records;
    int copy_count;

    entry->questions.count = 0;
    end = lines->str + lines->len;
    p = lines->str;
    while (p < end) {
        line.str = p;
        p = memchr(p, '\n', end - p);
        if (p != NULL) {
            line.len = p - line.str;
            p++; //skip \n
        } else {
            line.len = end - line.str;
            p = end;
        }

        FC_STRING_TRIM(&line);
        if (line.len == 0) {
            continue;
        }

        logInfo("lines==== %.*s", FC_PRINTF_STAR_STRING_PARAMS(line));

        parse_a_question(context, &line, &records);
        if (entry->questions.count + records.count > MAX_KEYWORDS_ROWS) {
            logWarning("file: "__FILE__", line: %d, "
                    "keyword rows exceeds %d",
                    __LINE__, MAX_KEYWORDS_ROWS);
            copy_count = MAX_KEYWORDS_ROWS - entry->questions.count;
        } else {
            copy_count = records.count;
        }

        if (copy_count > 0) {
            memcpy(entry->questions.rows + entry->questions.count,
                    records.rows, sizeof(KeywordArray) * copy_count);
            entry->questions.count += copy_count;
            if (entry->questions.count == MAX_KEYWORDS_ROWS) {
                break;
            }
        }
    }

    //print_keyword_records(&entry->questions);
    return 0;
}

static int compare_key_and_values(const ConditionEntry *entry1,
        const ConditionEntry *entry2)
{
    int result;
    int sub;
    int i;

    if ((result=fc_string_compare(&entry1->key, &entry2->key)) != 0) {
        return result;
    }

    sub = entry1->values.count - entry2->values.count;
    if (sub != 0) {
        return sub;
    }

    for (i=0; i<entry1->values.count; i++) {
        if ((result=fc_string_compare(&entry1->values.strings[i],
                        &entry2->values.strings[i])) != 0)
        {
            return result;
        }
    }

    return 0;
}

static int compare_answer_conditions(const ConditionArray *cond1,
        const ConditionArray *cond2)
{
    int sub;
    int result;
    int i;

    sub = cond1->count - cond2->count;
    if (sub != 0) {
        return sub;
    }

    for (i=0; i<cond1->count; i++) {
        if ((result=compare_key_and_values(cond1->kv_pairs + i,
                        cond2->kv_pairs + i)) != 0)
        {
            return result;
        }
    }

    return 0;
}

static int compare_by_answer_conditions(const ConditionAnswerEntry *entry1,
        const ConditionAnswerEntry *entry2)
{
    return compare_answer_conditions(&entry1->conditions, &entry2->conditions);
}

static int clone_string_array(QAReaderContext *context,
        string_array_t *dest, const string_array_t *src)
{
    int bytes;
    int result;
    const string_t *src_str;
    const string_t *src_end;
    string_t *dst_str;

    bytes = sizeof(string_t) * src->count;
    dest->strings = (string_t *)fast_mpool_alloc(
            context->mpool, bytes);
    if (dest->strings == NULL) {
        logError("file: "__FILE__", line: %d, "
                "alloc %d bytes from mpool fail", __LINE__, bytes);
        return ENOMEM;
    }

    src_end = src->strings + src->count;
    for (src_str=src->strings,dst_str=dest->strings; src_str<src_end;
            src_str++,dst_str++)
    {
        if ((result=fast_mpool_strdup2(context->mpool,
                        dst_str, src_str)) != 0)
        {
            return result;
        }
    }

    dest->count = src->count;
    return 0;
}

static int add_unique_answers(QAReaderContext *context,
        ConditionAnswerEntry *answer_entries, const int count,
        ConditionAnswerArray *answer_array)
{
    ConditionAnswerEntry sorted_entries[QA_MAX_ANSWER_ENTRIES];
    ConditionAnswerEntry *unique_entries[QA_MAX_ANSWER_ENTRIES];
    ConditionAnswerEntry *p;
    ConditionAnswerEntry *end;
    ConditionAnswerEntry **dest;
    ConditionEntry *kv_pairs;
    ConditionEntry *kv;
    ConditionEntry *kv_end;
    ConditionEntry  *kv_dest;
    int result;
    int unique_count;
    int kv_count;
    int bytes;
    int i;

    if (count <= 1) {
        unique_count = count;
        *unique_entries = answer_entries;
    } else {
        memcpy(sorted_entries, answer_entries,
                sizeof(ConditionAnswerEntry) * count);
        qsort(sorted_entries, count, sizeof(ConditionAnswerEntry),
                (int (*)(const void *, const void *))compare_by_answer_conditions);
       
        end = sorted_entries + count;
        dest = unique_entries;
        *dest++ = sorted_entries;
        for (p=sorted_entries + 1; p<end; p++) {
            if (compare_by_answer_conditions(p, p-1) != 0) {
                *dest++ = p;
            }
        }

        unique_count = dest - unique_entries;
    }

    bytes = sizeof(ConditionAnswerEntry) * unique_count;
    answer_array->entries = (ConditionAnswerEntry *)fast_mpool_alloc(
            context->mpool, bytes);
    if (answer_array->entries == NULL) {
        logError("file: "__FILE__", line: %d, "
                "alloc %d bytes from mpool fail", __LINE__, bytes);
        return ENOMEM;
    }

    for (i=0; i<unique_count; i++) {
        kv_count = unique_entries[i]->conditions.count;
        answer_array->entries[i].conditions.count = kv_count;
        if (kv_count == 0) {
            kv_pairs = NULL;
        } else {
            bytes = sizeof(ConditionEntry) * kv_count;
            kv_pairs = (ConditionEntry *)fast_mpool_alloc(
                    context->mpool, bytes);
            if (kv_pairs == NULL) {
                logError("file: "__FILE__", line: %d, "
                        "alloc %d bytes from mpool fail", __LINE__, bytes);
                return ENOMEM;
            }

            kv_dest = kv_pairs;
            kv_end = unique_entries[i]->conditions.kv_pairs + kv_count;
            for (kv=unique_entries[i]->conditions.kv_pairs; kv<kv_end; kv++) {
                if ((result=fast_mpool_strdup2(context->mpool,
                                &kv_dest->key, &kv->key)) != 0)
                {
                    return result;
                }

                if ((result=clone_string_array(context, &kv_dest->values,
                                &kv->values)) != 0)
                {
                    return result;
                }
                kv_dest++;
            }
        }

        answer_array->entries[i].conditions.kv_pairs = kv_pairs;
    }

    answer_array->count = unique_count;
    return 0;
}

static int combine_answer_string(QAReaderContext *context,
        ConditionAnswerEntry *answer_entries, const int count,
        ConditionAnswerArray *answer_array)
{
    ConditionAnswerEntry *entry;
    ConditionAnswerEntry *end;
    ConditionAnswerEntry *fp;
    ConditionAnswerEntry *fend;
    int result;

    fend = answer_entries + count;
    end = answer_array->entries + answer_array->count;
    for (entry=answer_array->entries; entry<end; entry++) {

        fast_buffer_clear(context->buffer);
        for (fp=answer_entries; fp<fend; fp++) {
            if (fp->conditions.count == 0 || compare_by_answer_conditions(
                        fp, entry) == 0)
            {
                if ((result=fast_buffer_append_string2(context->buffer,
                                &fp->answer)) != 0)
                {
                    return result;
                }
            }
        }

        if ((result=fast_mpool_strdup_ex(context->mpool, &entry->answer,
                context->buffer->data, context->buffer->length)) != 0)
        {
            return result;
        }
    }

    return 0;
}

static int qa_reader_combine_answer(QAReaderContext *context,
        ConditionAnswerEntry *answer_entries, const int count,
        QAReaderEntry *entry)
{
    ConditionAnswerEntry *p;
    ConditionAnswerEntry *end;
    ConditionAnswerArray *answer_array;
    int result;

    end = answer_entries + count;
    for (p=answer_entries; p<end; p++) {
        if (p->conditions.count > 1) {
            qsort(p->conditions.kv_pairs, p->conditions.count,
                    sizeof(key_value_pair_t),
                    (int (*)(const void *, const void *))compare_key_and_values);
        }
    }

    answer_array = &entry->answer.condition_answers;

    if ((result=add_unique_answers(context, answer_entries,
                    count, answer_array)) != 0)
    {
        return result;
    }

    if ((result=combine_answer_string(context, answer_entries,
                    count, answer_array)) != 0)
    {
        return result;
    }

    /*
    logInfo("======answer count====== %d", answer_array->count);

    end = answer_array->entries + answer_array->count;
    for (p=answer_array->entries; p<end; p++) {
        key_value_pair_t *kv;
        key_value_pair_t *kv_end;

        printf("kv count: %d\n", p->conditions.count);

        kv_end = p->conditions.kv_pairs + p->conditions.count;
        for (kv=p->conditions.kv_pairs; kv<kv_end; kv++) {
            printf("%.*s=%.*s ", FC_PRINTF_STAR_STRING_PARAMS(kv->key),
                    FC_PRINTF_STAR_STRING_PARAMS(kv->value));
        }
        printf("\n answer::::::\n");
        printf("$$$$$$$$$$$$$$$$\n");
        printf("%.*s",
                FC_PRINTF_STAR_STRING_PARAMS(p->answer));
        printf("$$$$$$$$$$$$$$$$\n");
    }
    */

    return 0;
}

static int qa_reader_parse_func_params(string_t *params,
        ConditionEntry *condition, string_t **values)
{
    return 0;
}

static int qa_reader_parse_condition(key_value_pair_t *kv,
        ConditionEntry *condition, string_t **values)
{
    string_t func_name;
    char *p;
    char *end;
    string_t params;

    condition->key = kv->key;
    do {
        if (!(kv->value.len > 2 && kv->value.str[kv->value.len - 1] == ')')) {
            break;
        }

        func_name.str = p = kv->value.str;
        end = kv->value.str + kv->value.len;
        while (p < end && FC_IS_LETTER(*p)) {
            p++;
        }
        func_name.len = p - func_name.str;

        while (p < end && (*p == ' ' || *p == '\t')) {
            p++;
        }
        if (*p != '(') {
            break;
        }

        if (fc_string_equal2(&func_name, FUNC_IN_STR, FUNC_IN_LEN)) {
            condition->op_type = CONDITION_OPERATOR_IN;
        } else {
            break;
        }

        params.str = p + 1;
        params.len = (end - 1) - params.str;
        return qa_reader_parse_func_params(&params, condition, values);
    } while (0);

    condition->op_type = CONDITION_OPERATOR_EQ;
    condition->values.count = 1;
    condition->values.strings = (*values)++;
    condition->values.strings[0] = kv->value;

    return 0;
}

static int qa_reader_set_answer(QAReaderContext *context,
        QATagInfo *atag, const string_t *answer,
        ConditionAnswerEntry *entry, QAConditionHolder *condition_holder)
{
    int result;
    QATagAttributeArray attributes;
    key_value_pair_t *kv;
    key_value_pair_t *kv_end;
    ConditionEntry *condition;
    string_t *values;

    if ((result=qa_reader_parse_attributes(context, atag, &attributes)) != 0) {
        return result;
    }

    entry->answer = *answer;
    entry->conditions.count = attributes.count;
    entry->conditions.kv_pairs = condition_holder->kv_pairs;

    values = condition_holder->values;
    condition = condition_holder->kv_pairs;
    kv_end = attributes.kv_pairs + attributes.count;
    for (kv=attributes.kv_pairs; kv<kv_end; kv++) {
        if ((result=qa_reader_parse_condition(kv, condition, &values)) != 0) {
            break;
        }

        condition++;
    }

    return result;
}

static int qa_reader_parse_answer(QAReaderContext *context,
        QATagInfo *atag, QAReaderEntry *entry)
{
    QATagInfo next_tags[2];
    QATagInfo *next_atag;
    QATagInfo *current_tag;

    ConditionAnswerEntry answers[QA_MAX_ANSWER_ENTRIES];
    QAConditionHolder condition_holders[QA_MAX_ANSWER_ENTRIES];
    QAConditionHolder *current_holder;
    string_t answer;
    int result;
    int count;

    current_holder = condition_holders;
    count = 0;
    while (atag != NULL) {
        current_tag = next_tags + (count % 2);
        context->p = atag->next;   //skip answer tag
        answer.str = atag->next;
        if (get_first_end_tag(context,
                    TAG_QUESTION_STR, TAG_QUESTION_LEN,
                    TAG_ANSWER_STR, TAG_ANSWER_LEN,
                    current_tag) == 0)
        {
            logWarning("file: "__FILE__", line: %d, "
                    "=====first end tag in file: %s, tag: %.*s=====",
                    __LINE__, context->filename,
                    QA_SHOW_CONTENT_LENGTH((int)(current_tag->end - current_tag->start)),
                    current_tag->start);

            if (fc_string_equal2(&current_tag->name, TAG_QUESTION_STR,
                        TAG_QUESTION_LEN))
            {
                context->p = current_tag->start;
                next_atag = NULL;
            } else {
                next_atag = current_tag;
            }
            answer.len = current_tag->start - answer.str;
        } else {
            next_atag = NULL;
            context->p = context->end;
            answer.len = context->end - answer.str;
        }

        if (count >= QA_MAX_ANSWER_ENTRIES) {
            logWarning("file: "__FILE__", line: %d, "
                    "answer count exceeds %d",
                    __LINE__, QA_MAX_ANSWER_ENTRIES);
            result = ENOSPC;
            break;
        }

        if ((result=qa_reader_set_answer(context, atag,
                        &answer, answers + count, current_holder++)) != 0)
        {
            break;
        }

        atag = next_atag;
        count++;
    }

    if ((result=qa_reader_combine_answer(context, answers, count, entry)) != 0) {
        return result;
    }

    return 0;
}

int qa_reader_next(QAReaderContext *context, QAReaderEntry *entry)
{
    int result;
    int qr;
    int ar;
    int64_t question_id;
    string_t question;
    QATagInfo qtag;
    QATagInfo atag;

    if (context->p == context->end) {
        return ENOENT;
    }

    while (context->p < context->end) {
        if ((result=qa_reader_next_tag(context, &qtag)) != 0) {
            return result;
        }

        if (fc_string_equal2(&qtag.name, TAG_QUESTION_STR, TAG_QUESTION_LEN)) {
            break;
        }

        context->p = qtag.end;   //skip tag
        logWarning("file: "__FILE__", line: %d, "
                "skip tag in file: %s, tag: %.*s",
                __LINE__, context->filename, QA_SHOW_CONTENT_LENGTH(
                    (int)(qtag.end - qtag.start)), qtag.start);
    }

    context->p = qtag.end;   //skip tag
    if ((result=qa_reader_get_attribute_id(context, &qtag, &question_id)) != 0) {
        return result;
    }

    question.str = qtag.next;

    question_id += context->base_id;
    logInfo("question_id===== %"PRId64, question_id);


    result = qa_reader_next_tag(context, &atag);
    if (result != 0 || !fc_string_equal2(&atag.name,
                TAG_ANSWER_STR, TAG_ANSWER_LEN))
    {
        logWarning("file: "__FILE__", line: %d, "
                "expect %s tag in file: %s, tag: %.*s",
                __LINE__, TAG_ANSWER_STR, context->filename,
                QA_SHOW_CONTENT_LENGTH((int)(qtag.end - qtag.start)),
                qtag.start);
        return EINVAL;
    }

    entry->answer.id = question_id;

        logWarning("file: "__FILE__", line: %d, "
                "%s tag in file: %s, tag: %.*s",
                __LINE__, TAG_ANSWER_STR, context->filename,
                QA_SHOW_CONTENT_LENGTH((int)(atag.end - atag.start)),
                atag.start);

    question.len = atag.start - question.str;
    qr = qa_reader_parse_question(context, &question, entry);
    ar = qa_reader_parse_answer(context, &atag, entry);
    return qr == 0 ? ar : qr;
}
