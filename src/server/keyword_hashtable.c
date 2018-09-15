#include <netdb.h>
#include <unistd.h>
#include <errno.h>
#include "fastcommon/logger.h"
#include "fastcommon/hash.h"
#include "fastcommon/shared_func.h"
#include "wordsegment.h"
#include "qa_loader.h"
#include "keyword_hashtable.h"

static int hashtable_init(KeywordHashtableContext *context,
        KeywordHashtable **htable, const int capacity)
{
    unsigned int *pcapacity;
    int bytes;

    pcapacity = hash_get_prime_capacity(capacity);
    if (pcapacity == NULL) {
        logError("file: "__FILE__", line: %d, "
                "capacity: %d is too large", __LINE__, capacity);
        return EOVERFLOW;
    }

    *htable = (KeywordHashtable *)fast_mblock_alloc_object(
            &context->htable_allocator);
    if (*htable == NULL) {
        logError("file: "__FILE__", line: %d, "
                "alloc hashtable fail", __LINE__);
        return ENOMEM;
    }

    (*htable)->capacity = *pcapacity;
    bytes = sizeof(KeywordHashEntry *) * (*htable)->capacity;
    (*htable)->buckets = (KeywordHashEntry **)malloc(bytes);
    if ((*htable)->buckets == NULL) {
        logError("file: "__FILE__", line: %d, "
                "malloc %d bytes fail", __LINE__, bytes);
        return ENOMEM;
    }

    memset((*htable)->buckets, 0, bytes);
    return 0;
}

static KeywordHashEntry *hashtable_find(KeywordHashtable *htable,
        const string_t *ch)
{
    KeywordHashEntry *current;
    unsigned int hash_code;
    unsigned int index;

    hash_code = simple_hash(ch->str, ch->len);
    index = hash_code % htable->capacity;
    current = htable->buckets[index];
    while (current != NULL) {
        if (fc_string_equal(&current->ch, ch)) {
            return current;
        }
        current = current->next;
    }

    return NULL;
}

static KeywordHashEntry *hashtable_insert(KeywordHashtableContext *context,
        KeywordHashtable *htable, const string_t *ch, const string_t *similar,
        const string_t *keyword)
{
    KeywordHashEntry *hentry;
    unsigned int hash_code;
    unsigned int index;

    hentry = (KeywordHashEntry *)fast_mblock_alloc_object(
            &context->hentry_allocator);
    if (hentry == NULL) {
        logError("file: "__FILE__", line: %d, "
                "alloc hash entry fail", __LINE__);
        return NULL;
    }

    if (fast_mpool_strdup2(&context->string_allocator, &hentry->ch, ch) != 0) {
        return NULL;
    }

    if (fast_mpool_strdup2(&context->string_allocator, &hentry->keyword,
                keyword) != 0)
    {
        return NULL;
    }
    if (fc_string_equal(keyword, similar)) {
        hentry->similar = hentry->keyword;
    } else {
        if (fast_mpool_strdup2(&context->string_allocator, &hentry->similar,
                    similar) != 0)
        {
            return NULL;
        }
    }

    hash_code = simple_hash(ch->str, ch->len);
    index = hash_code % htable->capacity;
    hentry->next = htable->buckets[index];
    htable->buckets[index] = hentry;
    return hentry;
}

static KeywordHashEntry *insert_char(KeywordHashtableContext *context,
        KeywordHashtable **htable, const int level,
        const string_t *ch, const string_t *similar, const string_t *keyword)
{
    int capacity;
    int result;
    KeywordHashEntry *hentry;

    if (*htable == NULL) {
        capacity = context->top_capacity / level;
        if ((result=hashtable_init(context, htable, capacity)) != 0) {
            return NULL;
        }
    } else {
        hentry = hashtable_find(*htable, ch);
        if (hentry != NULL) {
            /* not keyword, do NOT change the similar of hentry */
            if (similar->len == 0) {
                return hentry;
            }

            if (hentry->similar.len == 0) {
                if ((result=fast_mpool_strdup2(&context->string_allocator,
                                &hentry->similar, similar)) != 0)
                {
                    return NULL;
                }
            }
            else if (!fc_string_equal(&hentry->similar, similar)) {
                logWarning("file: "__FILE__", line: %d, "
                        "keyword %.*s similar is: %.*s, "
                        "SKIPPING change to %.*s",
                        __LINE__, FC_PRINTF_STAR_STRING_PARAMS(*keyword),
                        FC_PRINTF_STAR_STRING_PARAMS(hentry->similar),
                        FC_PRINTF_STAR_STRING_PARAMS(*similar));
            }

            return hentry;
        }
    }

    return hashtable_insert(context, *htable, ch, similar, keyword);
}

KeywordHashEntry *keyword_hashtable_insert_ex(KeywordHashtableContext *context,
        const string_t *keyword, const string_t *similar)
{
    string_t ch;
    const char *p;
    const char *end;
    string_t empty;
    int i;
    KeywordHashtable **htable;
    KeywordHashEntry *hentry;

    hentry = NULL;
    htable = &context->top;
    p = keyword->str;
    end = keyword->str + keyword->len;

    FC_SET_STRING_NULL(empty);
    i = 0;
    while (p < end) {
        if (word_segment_next_word(&p, end, &ch) != 0) {
            continue;
        }

        logInfo("word[%d]: %.*s, last: %d",
                i, ch.len, ch.str, p == end);

        if ((hentry=insert_char(context, htable, ++i, &ch,
                        (p == end) ? similar : &empty, keyword)) == NULL)
        {
            return NULL;
        }

        htable = &hentry->children;
    }

    return hentry;
}

KeywordHashEntry *keyword_hashtable_find(KeywordHashtableContext *context,
        const string_t *keyword)
{
    string_t ch;
    const char *p;
    const char *end;
    KeywordHashtable **htable;
    KeywordHashEntry *hentry;

    htable = &context->top;
    p = keyword->str;
    end = keyword->str + keyword->len;

    int i = 0;
    while (p < end) {
        if (word_segment_next_word(&p, end, &ch) != 0) {
            continue;
        }

        logInfo("finding WORD[%d]: %.*s, last: %d",
                i++, ch.len, ch.str, p == end);

        hentry = hashtable_find(*htable, &ch);
        if (hentry == NULL) {
            return NULL;
        }

        if (p == end) {
            return hentry;
        }

        htable = &hentry->children;
        if (*htable == NULL) {
            return NULL;
        }
    }

    return NULL;
}

KeywordHashEntry *keyword_hashtable_find_ex(KeywordHashtableContext *context,
        const string_t *chs, const int count)
{
    const string_t *p;
    const string_t *end;
    KeywordHashtable **htable;
    KeywordHashEntry *hentry;

    htable = &context->top;
    p = chs;
    end = chs + count;

    int i = 0;
    while (p < end) {

        logInfo("finding WORD[%d]: %.*s(%d), last: %d",
                i++, FC_PRINTF_STAR_STRING_PARAMS(*p),
                p->len, p == end);

        hentry = hashtable_find(*htable, p);
        if (hentry == NULL) {
            return NULL;
        }

        if (++p == end) {
            return hentry;
        }

        htable = &hentry->children;
        if (*htable == NULL) {
            return NULL;
        }
    }

    return NULL;
}

static int split_similar_keywords(char *line, string_t *keywords,
        const int max)
{
    char *p;
    char *end;
    string_t *dest;

    dest = keywords;
    p = line;
    end = p + strlen(line);
    while (p < end) {
        while ((p < end) && (*p == ' ' || *p == '\t')) {
            p++;
        }
        if (p == end) {
            break;
        }

        if (dest - keywords >= max) {
                logWarning("file: "__FILE__", line: %d, "
                        "too many keywords exceeds %d in similar file",
                        __LINE__, max);
                break;
        }

        if (*p == '(') {
            dest->str = ++p;
            while ((p < end) && (*p != ')')) {
                p++;
            }
            if (p == end) {
                logWarning("file: "__FILE__", line: %d, "
                        "expect ) in similar file, line: %s",
                        __LINE__, line);
            }
        } else {
            dest->str = p;
            while ((p < end) && !(*p == ' ' || *p == '\t')) {
                p++;
            }
        }
        dest->len = p - dest->str;
        dest++;
        p++; //skip seperator
    }

    return dest - keywords;
}

static KeywordHashEntry *insert_keyword_and_similar(
        KeywordHashtableContext *context,
        string_t *keyword, const string_t *similar)
{
    string_t formatted;
    string_t concated;
    char fholder[256];
    char cholder[256];

    if (keyword->len > sizeof(fholder)) {
        logWarning("file: "__FILE__", line: %d, "
                "keywords length %d exceeds %d",
                __LINE__, keyword->len, (int)sizeof(fholder));
        return NULL;
    }

    formatted.str = fholder;
    concated.str = cholder;
    keyword_normalize(keyword, &formatted, &concated);
    if (formatted.len == 0) {
        return NULL;
    }

    if (concated.len > 0) {
        if (keyword_hashtable_insert_ex(context,
                    &concated, similar) == NULL)
        {
            return NULL;
        }
    }

    return keyword_hashtable_insert_ex(context, &formatted, similar);
}

static int similar_keywords_init(KeywordHashtableContext *context,
        const SimilarKeywordsInput *similars)
{
#define MAX_SIMILAR_WORDS_COUNT   128

    char **line;
    char **end;
    string_t *word;
    const string_t *similar;
    string_t keywords[MAX_SIMILAR_WORDS_COUNT];
    string_t *p;
    string_t *kend;
    int count;
    int result = 0;

    end = similars->lines + similars->count;
    for (line=similars->lines; line<end; line++) {
        if (**line == '\0') {
            continue;
        }
        count = split_similar_keywords(*line, keywords, MAX_SIMILAR_WORDS_COUNT);
        if (count <= 1) {
            logWarning("file: "__FILE__", line: %d, "
                    "invalid similar keywords: %s", __LINE__, *line);
            continue;
        }

        word = keywords + 0;
        similar = keyword_to_similar(word);

        kend = keywords + count;
        for (p = keywords + 1; p < kend; p++) {
            if (insert_keyword_and_similar(context, p, similar) == NULL) {
                result = ENOMEM;
                break;
            }
        }
    }

    return result;
}

int keyword_hashtable_init(KeywordHashtableContext *context, const int capacity,
        const SimilarKeywordsInput *similars)
{
    int result;

    context->top_capacity = capacity;
    context->top = NULL;
    if ((result=fast_mblock_init_ex(&context->hentry_allocator,
            sizeof(KeywordHashEntry), 102400, NULL, false)) != 0)
    {
        return result;
    }
    
    if ((result=fast_mblock_init_ex(&context->htable_allocator,
            sizeof(KeywordHashEntry), 10240, NULL, false)) != 0)
    {
        return result;
    }

    if ((result=fast_mpool_init(&context->string_allocator, 0, 32)) != 0) {
        return result;
    }

    if ((result=hashtable_init(context, &context->top, capacity)) != 0) {
        return result;
    }
    
    return similar_keywords_init(context, similars);
}

void keyword_hashtable_destroy(KeywordHashtableContext *context)
{
    fast_mblock_destroy(&context->hentry_allocator);
    fast_mblock_destroy(&context->htable_allocator);
    fast_mpool_destroy(&context->string_allocator);
}

int keyword_hashtable_add_keywords(KeywordHashtableContext *context,
        const KeywordArray *keywords)
{
    int result;
    const string_t *key;
    const string_t *end;

    result = 0;
    end = keywords->keywords + keywords->count;
    for (key=keywords->keywords; key<end; key++) {
        if ((result=keyword_hashtable_insert(context, key, key)) != 0) {
            if (result == EINVAL || result == EEXIST) {
                result = 0;
                continue;
            }
            break;
        }
    }

    return result;
}
