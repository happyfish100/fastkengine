#include <netdb.h>
#include <unistd.h>
#include <errno.h>
#include "fastcommon/logger.h"
#include "fastcommon/hash.h"
#include "fastcommon/shared_func.h"
#include "similar_words.h"

static int hashtable_init(SimilarWordsContext *context, const int capacity)
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
    bytes = sizeof(struct similar_words_hash_entry *) * context->htable.capacity;
    context->htable.buckets = (struct similar_words_hash_entry **)malloc(bytes);
    if (context->htable.buckets == NULL) {
        logError("file: "__FILE__", line: %d, "
                "malloc %d bytes fail", __LINE__, bytes);
        return ENOMEM;
    }

    memset(context->htable.buckets, 0, bytes);
    return 0;
}

static SimilarWordsHashEntry *hashtable_find(SimilarWordsContext *context,
        const string_t *word)
{
    SimilarWordsHashEntry *current;
    unsigned int hash_code;
    unsigned int index;

    hash_code = simple_hash(word->str, word->len);
    index = hash_code % context->htable.capacity;
    current = context->htable.buckets[index];
    while (current != NULL) {
        if (fc_string_equal(&current->word, word)) {
            return current;
        }
        current = current->next;
    }

    return NULL;
}


static int alloc_string(SimilarWordsContext *context, string_t *dest,
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

static SimilarWordsHashEntry *hashtable_insert(SimilarWordsContext *context,
        const string_t *word, const string_t *similar)
{
    SimilarWordsHashEntry *hentry;
    unsigned int hash_code;
    int result;
    unsigned int index;

    hentry = (SimilarWordsHashEntry *)fast_mblock_alloc_object(
            &context->hentry_allocator);
    if (hentry == NULL) {
        logError("file: "__FILE__", line: %d, "
                "alloc hash entry fail", __LINE__);
        return NULL;
    }

    if ((result=alloc_string(context, &hentry->word, word)) != 0) {
        return NULL;
    }
    if ((result=alloc_string(context, &hentry->similar, similar)) != 0) {
        return NULL;
    }

    hash_code = simple_hash(word->str, word->len);
    index = hash_code % context->htable.capacity;
    hentry->next = context->htable.buckets[index];
    context->htable.buckets[index] = hentry;
    return hentry;
}

static int insert_entry(SimilarWordsContext *context,
        const string_t *word, const string_t *similar)
{
    SimilarWordsHashEntry *hentry;

    hentry = hashtable_find(context, word);
    if (hentry != NULL) {
        logError("file: "__FILE__", line: %d, "
                "keyword %.*s already exists, similar is: %.*s",
                __LINE__, word->len, word->str,
                hentry->similar.len, hentry->similar.str);
        return EEXIST;
    }

    return hashtable_insert(context, word, similar) != NULL ? 0 : ENOMEM;
}

int similar_words_init(SimilarWordsContext *context, const int capacity,
            char **lines, const int count, const char seperator)
{
#define MAX_SIMILAR_WORDS_COUNT   128

    char **line;
    char **end;
    string_t word;
    string_t similar;
    char *keywords[MAX_SIMILAR_WORDS_COUNT];
    int n;
    int i;
    int result;

    if ((result=fast_mblock_init_ex(&context->hentry_allocator,
            sizeof(SimilarWordsHashEntry), 102400, NULL, false)) != 0)
    {
        return result;
    }

    if ((result=fast_mpool_init(&context->string_allocator, 0, 32)) != 0) {
        return result;
    }
    
    if ((result=hashtable_init(context, capacity)) != 0) {
        return result;
    }

    end = lines + count;
    for (line=lines; line<end; line++) {
        n = splitEx(*line, seperator, keywords, MAX_SIMILAR_WORDS_COUNT);
        if (n <= 1) {
            logWarning("file: "__FILE__", line: %d, "
                    "invalid similar keywords: %s", __LINE__, *line);
            continue;
        }

        FC_SET_STRING(similar, keywords[0]);
        for (i=1; i<n; i++) {
            FC_SET_STRING(word, keywords[i]);
            if ((result=insert_entry(context, &word, &similar)) != 0) {
                break;
            }
        }
    }

    return result;
}

void similar_words_destroy(SimilarWordsContext *context)
{
    fast_mblock_destroy(&context->hentry_allocator);
    fast_mpool_destroy(&context->string_allocator);
    free(context->htable.buckets);
    context->htable.buckets = NULL;
}

const string_t *similar_words_find(SimilarWordsContext *context,
        const string_t *keyword)
{
    SimilarWordsHashEntry *hentry;
    if ((hentry=hashtable_find(context, keyword)) == NULL) {
        return NULL;
    }

    return &hentry->similar;
}
