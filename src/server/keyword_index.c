#include <netdb.h>
#include <unistd.h>
#include <errno.h>
#include "fastcommon/logger.h"
#include "fastcommon/hash.h"
#include "fastcommon/shared_func.h"
#include "keyword_index.h"

#define KEYWORDS_SEPERATOR   '\x1'

static int keywords_to_string(QuestionEntry *qentry,
        const KeywordArray *keywords)
{
    int i;

    qentry->question.str = qentry->buff;
    if (keywords->count == 0) {
        qentry->question.len = 0;
        logError("file: "__FILE__", line: %d, "
                "no keyword", __LINE__);
        return EINVAL;
    }

    qentry->question.len = snprintf(qentry->buff, sizeof(qentry->buff),
            "%.*s", FC_PRINTF_STAR_STRING_PARAMS(keywords->keywords[0]));
    if (qentry->question.len >= sizeof(qentry->buff)) {
        logError("file: "__FILE__", line: %d, "
                "exceeds buffer size: %d", __LINE__,
                (int)sizeof(qentry->buff));
        qentry->question.len = sizeof(qentry->buff) - 1;
        return ENOSPC;
    }

    for (i=1; i<keywords->count; i++) {
        qentry->question.len += snprintf(qentry->buff + qentry->question.len,
                sizeof(qentry->buff) - qentry->question.len,
                "%c%.*s", KEYWORDS_SEPERATOR,
                FC_PRINTF_STAR_STRING_PARAMS(keywords->keywords[i]));
        if (qentry->question.len >= sizeof(qentry->buff)) {
            logError("file: "__FILE__", line: %d, "
                    "exceeds buffer size: %d", __LINE__,
                    (int)sizeof(qentry->buff));
            qentry->question.len = sizeof(qentry->buff) - 1;
            return ENOSPC;
        }
    }

    return 0;
}

static int hashtable_init(KeywordIndexContext *context, const int capacity)
{
    unsigned int *pcapacity;
    int bytes;

    pcapacity = hash_get_prime_capacity(capacity);
    if (pcapacity == NULL) {
        logError("file: "__FILE__", line: %d, "
                "capacity: %d is too large", __LINE__, capacity);
        return EOVERFLOW;
    }

    context->htable.capacity = *pcapacity;
    bytes = sizeof(struct keyword_index_hash_entry *) * context->htable.capacity;
    context->htable.buckets = (struct keyword_index_hash_entry **)malloc(bytes);
    if (context->htable.buckets == NULL) {
        logError("file: "__FILE__", line: %d, "
                "malloc %d bytes fail", __LINE__, bytes);
        return ENOMEM;
    }

    memset(context->htable.buckets, 0, bytes);
    return 0;
}

static KeywordIndexHashEntry *hashtable_find(KeywordIndexContext *context,
        const string_t *question)
{
    KeywordIndexHashEntry *current;
    unsigned int hash_code;
    unsigned int index;

    hash_code = simple_hash(question->str, question->len);
    index = hash_code % context->htable.capacity;
    current = context->htable.buckets[index];
    while (current != NULL) {
        if (fc_string_equal(&current->question, question)) {
            return current;
        }
        current = current->next;
    }

    return NULL;
}


static int alloc_string(KeywordIndexContext *context, string_t *dest,
        const string_t *src)
{
    dest->str = (char *)fast_mpool_alloc(&context->string_allocator, src->len);
    if (dest->str == NULL) {
        logError("file: "__FILE__", line: %d, "
                "alloc %d bytes from mpool fail", __LINE__, src->len);
        return ENOMEM;
    }

    memcpy(dest->str, src->str, src->len);
    dest->len = src->len;
    return 0;
}

static KeywordIndexHashEntry *hashtable_insert(KeywordIndexContext *context,
        const string_t *question, AnswerEntry *answer)
{
    KeywordIndexHashEntry *hentry;
    unsigned int hash_code;
    int result;
    unsigned int index;

    hentry = (KeywordIndexHashEntry *)fast_mblock_alloc_object(
            &context->hentry_allocator);
    if (hentry == NULL) {
        logError("file: "__FILE__", line: %d, "
                "alloc hash entry fail", __LINE__);
        return NULL;
    }

    if ((result=alloc_string(context, &hentry->question, question)) != 0) {
        return NULL;
    }
    hentry->answer = answer;

    hash_code = simple_hash(question->str, question->len);
    index = hash_code % context->htable.capacity;
    hentry->next = context->htable.buckets[index];
    context->htable.buckets[index] = hentry;
    return hentry;
}

static int insert_entry(KeywordIndexContext *context,
        const string_t *question, AnswerEntry *answer)
{
    KeywordIndexHashEntry *hentry;

    hentry = hashtable_find(context, question);
    if (hentry != NULL) {
        logError("file: "__FILE__", line: %d, "
                "keyword %.*s already exists",
                __LINE__, question->len, question->str);
        return EEXIST;
    }

    return hashtable_insert(context, question, answer) != NULL ? 0 : ENOMEM;
}

int keyword_index_init(KeywordIndexContext *context, const int capacity)
{
    int result;

    if ((result=fast_mblock_init_ex(&context->hentry_allocator,
            sizeof(KeywordIndexHashEntry), 102400, NULL, false)) != 0)
    {
        return result;
    }

    if ((result=fast_mpool_init(&context->string_allocator, 0, 32)) != 0) {
        return result;
    }
    
    if ((result=hashtable_init(context, capacity)) != 0) {
        return result;
    }

    return result;
}

void keyword_index_destroy(KeywordIndexContext *context)
{
    fast_mblock_destroy(&context->hentry_allocator);
    fast_mpool_destroy(&context->string_allocator);
    free(context->htable.buckets);
    context->htable.buckets = NULL;
}

int keyword_index_add(KeywordIndexContext *context,
        const KeywordArray *keywords, AnswerEntry *answer)
{
    QuestionEntry qentry;
    int result;

    if ((result=keywords_to_string(&qentry, keywords)) != 0) {
        return result;
    }

    return insert_entry(context, &qentry.question, answer);
}

const AnswerEntry *keyword_index_find(KeywordIndexContext *context,
        const KeywordArray *keywords)
{
    QuestionEntry qentry;
    KeywordIndexHashEntry *hentry;

    if (keywords_to_string(&qentry, keywords) != 0) {
        return NULL;
    }

    if ((hentry=hashtable_find(context, &qentry.question)) == NULL) {
        return NULL;
    }

    return hentry->answer;
}
