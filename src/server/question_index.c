#include <netdb.h>
#include <unistd.h>
#include <errno.h>
#include "fastcommon/logger.h"
#include "fastcommon/hash.h"
#include "fastcommon/shared_func.h"
#include "question_index.h"

#define KEYWORDS_SEPERATOR   '\x1'

int question_index_key_length(const KeywordArray *keywords)
{
    int length;
    int i;

    if (keywords->count == 0) {
        return 0;
    }

    length = keywords->count - 1;   //seperator characters
    for (i=0; i<keywords->count; i++) {
        length += keywords->keywords[i].len;
    }
    return length;
}

static int keywords_to_string(QuestionBuffer *qentry,
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
    bytes = sizeof(struct question_index_hash_entry *) * context->htable.capacity;
    context->htable.buckets = (struct question_index_hash_entry **)malloc(bytes);
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
        if (fc_string_equal(&current->question.q, question)) {
            return current;
        }
        current = current->next;
    }

    return NULL;
}

static KeywordIndexHashEntry *hashtable_insert(KeywordIndexContext *context,
        const string_t *question, AnswerEntry *answer,
        const KeywordArray *karray)
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

    if ((result=fast_mpool_strdup2(&context->string_allocator,
                    &hentry->question.q, question)) != 0)
    {
        return NULL;
    }
    hentry->question.karray.count = karray->count;
    memcpy(hentry->question.karray.keywords, karray->keywords,
            sizeof(string_t) * karray->count);
    hentry->answer = *answer;

    hash_code = simple_hash(question->str, question->len);
    index = hash_code % context->htable.capacity;
    hentry->next = context->htable.buckets[index];
    context->htable.buckets[index] = hentry;
    return hentry;
}

static int insert_entry(KeywordIndexContext *context,
        const string_t *question, AnswerEntry *answer,
        const KeywordArray *karray)
{
    KeywordIndexHashEntry *hentry;

    hentry = hashtable_find(context, question);
    if (hentry != NULL) {
        logError("file: "__FILE__", line: %d, "
                "keyword %.*s already exists",
                __LINE__, question->len, question->str);
        return EEXIST;
    }

    return hashtable_insert(context, question, answer, karray)
        != NULL ? 0 : ENOMEM;
}

int question_index_init(KeywordIndexContext *context, const int capacity)
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

void question_index_destroy(KeywordIndexContext *context)
{
    fast_mblock_destroy(&context->hentry_allocator);
    fast_mpool_destroy(&context->string_allocator);
    free(context->htable.buckets);
    context->htable.buckets = NULL;
}

static int question_index_add(KeywordIndexContext *context,
        const KeywordArray *keywords, AnswerEntry *answer)
{
    QuestionBuffer qentry;
    int result;

    if ((result=keywords_to_string(&qentry, keywords)) != 0) {
        return result;
    }

    return insert_entry(context, &qentry.question, answer, keywords);
}

int question_index_adds(KeywordIndexContext *context,
        const KeywordRecords *records, AnswerEntry *answer)
{
    const KeywordArray *p;
    const KeywordArray *end;
    int r;
    int result = 0;

    end = records->rows + records->count;
    for (p=records->rows; p<end; p++) {
       if ((r=question_index_add(context, p, answer)) != 0) {
           result = r;
       }
    }
    return result;
}

int question_index_find(KeywordIndexContext *context,
        const KeywordArray *keywords, QAEntry *qa)
{
    int result;
    QuestionBuffer qentry;
    KeywordIndexHashEntry *hentry;

    if ((result=keywords_to_string(&qentry, keywords)) != 0) {
        return result;
    }

    if ((hentry=hashtable_find(context, &qentry.question)) == NULL) {
        return ENOENT;
    }

    qa->question = &hentry->question;
    qa->answer = &hentry->answer;
    return 0;
}
