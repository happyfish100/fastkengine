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

#define QA_TAG_MAX_ATTRIBUTES   5
#define QA_SHOW_CONTENT_SIZE    256

#define TAG_BASE_STR      "base"
#define TAG_QUESTION_STR  "question"
#define TAG_ANSWER_STR    "answer"

#define TAG_BASE_LEN      (sizeof(TAG_BASE_STR) - 1)
#define TAG_QUESTION_LEN  (sizeof(TAG_QUESTION_STR) - 1)
#define TAG_ANSWER_LEN    (sizeof(TAG_ANSWER_STR) - 1)

#define ATTRIBUTE_ID_STR   "id"
#define ATTRIBUTE_ID_LEN   (sizeof(ATTRIBUTE_ID_STR) - 1)

typedef struct {
    string_t name;
    char *start;
    char *end;
} QATagInfo;

typedef struct {
    key_value_pair_t kv_pairs[QA_TAG_MAX_ATTRIBUTES];
    int count;
} QATagAttributeArray;

#define QA_SHOW_CONTENT_LENGTH(len) \
    (len > QA_SHOW_CONTENT_SIZE ? QA_SHOW_CONTENT_SIZE : len)

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
    tag->end += 2;
    return 0;
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
        const char *filename)
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

int qa_reader_next(QAReaderContext *context, QAReaderEntry *entry)
{
    int result;
    int64_t question_id;
    QATagInfo tag;

    if (context->p == context->end) {
        return ENOENT;
    }

    while (context->p < context->end) {
        if ((result=qa_reader_next_tag(context, &tag)) != 0) {
            return result;
        }

        if (fc_string_equal2(&tag.name, TAG_QUESTION_STR, TAG_QUESTION_LEN)) {
            break;
        }

        context->p = tag.end;   //skip tag
        logWarning("file: "__FILE__", line: %d, "
                "skip tag in file: %s, tag: %.*s",
                __LINE__, context->filename, QA_SHOW_CONTENT_LENGTH(
                    (int)(tag.end - tag.start)), tag.start);
    }

    context->p = tag.end;   //skip tag
    if ((result=qa_reader_get_attribute_id(context, &tag, &question_id)) != 0) {
        return result;
    }

    question_id += context->base_id;
    logInfo("question_id===== %"PRId64, question_id);

    logInfo("file: "__FILE__", line: %d, "
            "tag in file: %s, tag: %.*s",
            __LINE__, context->filename, QA_SHOW_CONTENT_LENGTH(
                (int)(tag.end - tag.start)), tag.start);
    return 0;
}
