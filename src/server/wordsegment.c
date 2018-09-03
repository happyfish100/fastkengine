#include <netdb.h>
#include <unistd.h>
#include <errno.h>
#include "fastcommon/logger.h"
#include "fastcommon/hash.h"
#include "fastcommon/shared_func.h"
#include "wordsegment.h"

static int hashtable_init(WordSegmentContext *context,
        WordSegmentHashTable **htable, const int capacity)
{
    unsigned int *pcapacity;
    int bytes;

    pcapacity = hash_get_prime_capacity(capacity);
    if (pcapacity == NULL) {
        logError("file: "__FILE__", line: %d, "
                "capacity: %d is too large", __LINE__, capacity);
        return EOVERFLOW;
    }

    *htable = (WordSegmentHashTable *)fast_mblock_alloc_object(
            &context->htable_allocator);
    if (*htable == NULL) {
        logError("file: "__FILE__", line: %d, "
                "alloc hashtable fail", __LINE__);
        return ENOMEM;
    }

    (*htable)->capacity = *pcapacity;
    bytes = sizeof(struct word_segment_hash_entry *) * (*htable)->capacity;
    (*htable)->buckets = (struct word_segment_hash_entry **)malloc(bytes);
    if ((*htable)->buckets == NULL) {
        logError("file: "__FILE__", line: %d, "
                "malloc %d bytes fail", __LINE__, bytes);
        return ENOMEM;
    }

    memset((*htable)->buckets, 0, bytes);
    return 0;
}

static WordSegmentHashEntry *hashtable_find(WordSegmentHashTable *htable,
        const string_t *ch)
{
    WordSegmentHashEntry *current;
    unsigned int hash_code;
    int index;

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

static WordSegmentHashEntry *hashtable_insert(WordSegmentContext *context,
        WordSegmentHashTable *htable, const string_t *ch, const bool is_keyword)
{
    WordSegmentHashEntry *hentry;
    unsigned int hash_code;
    int index;

    hentry = (WordSegmentHashEntry *)fast_mblock_alloc_object(
            &context->hentry_allocator);
    if (hentry == NULL) {
        logError("file: "__FILE__", line: %d, "
                "alloc hash entry fail", __LINE__);
        return NULL;
    }

    hentry->ch.str = (char *)fast_mpool_alloc(&context->string_allocator, ch->len);
    if (hentry->ch.str == NULL) {
        logError("file: "__FILE__", line: %d, "
                "alloc %d bytes from mpool fail", __LINE__, ch->len);
        return NULL;
    }

    memcpy(hentry->ch.str, ch->str, ch->len);
    hentry->ch.len = ch->len;
    hentry->is_keyword = is_keyword;

    hash_code = simple_hash(ch->str, ch->len);
    index = hash_code % htable->capacity;
    hentry->next = htable->buckets[index];
    htable->buckets[index] = hentry;
    return hentry;
}

static WordSegmentHashEntry *insert_char(WordSegmentContext *context,
        WordSegmentHashTable **htable, const int level,
        const string_t *ch, const bool is_keyword)
{
    int capacity;
    int result;
    WordSegmentHashEntry *hentry;

    if (*htable == NULL) {
        capacity = context->top_capacity / level;
        if ((result=hashtable_init(context, htable, capacity)) != 0) {
            return NULL;
        }
    } else {
        hentry = hashtable_find(*htable, ch);
        if (hentry != NULL) {
            if (is_keyword && !hentry->is_keyword) {
                hentry->is_keyword = is_keyword;
            }
            return hentry;
        }
    }

    return hashtable_insert(context, *htable, ch, is_keyword);
}

static inline bool is_chinese_char(const string_t *keyword)
{
    if (keyword->len < 3) {
        return false;
    }

    return ((((unsigned char)keyword->str[0]) & 0xF0) == 0xE0) &&
        ((((unsigned char)keyword->str[1]) & 0xC0) == 0x80) &&
        ((((unsigned char)keyword->str[2]) & 0xC0) == 0x80);
}

static int insert_keyword(WordSegmentContext *context,
        const string_t *keyword)
{
    string_t ch;
    int i;
    WordSegmentHashTable **htable;
    WordSegmentHashEntry *hentry;

    if (keyword->len % 3 != 0) {
        logError("file: "__FILE__", line: %d, "
                "invalid Chinese characters length: %d, keyword: %.*s",
                __LINE__, keyword->len, keyword->len, keyword->str);
        return EINVAL;
    }

    htable = &context->top;
    for (i = 0; i < keyword->len; i += 3) {
        ch.str = keyword->str + i;
        ch.len = 3;
        if (!is_chinese_char(&ch)) {
            logError("file: "__FILE__", line: %d, "
                    "offset: %d, invalid Chinese characters, keyword: %.*s",
                    __LINE__, i, keyword->len, keyword->str);
            return EINVAL;
        }

        if ((hentry=insert_char(context, htable, i + 1,
                        &ch, i + 3 == keyword->len)) == 0)
        {
            return ENOMEM;
        }

        htable = &hentry->children;
    }

    return 0;
}

int word_segment_init(WordSegmentContext *context, const int top_capacity,
        const string_t *keywords, const int count)
{
    const string_t *key;
    const string_t *end;
    int result;

    context->top_capacity = top_capacity;
    context->top = NULL;

    if ((result=fast_mblock_init_ex(&context->hentry_allocator,
            sizeof(WordSegmentHashEntry), 102400, NULL, false)) != 0)
    {
        return result;
    }
    
    if ((result=fast_mblock_init_ex(&context->htable_allocator,
            sizeof(WordSegmentHashEntry), 10240, NULL, false)) != 0)
    {
        return result;
    }

    if ((result=fast_mpool_init(&context->string_allocator, 0, 16)) != 0) {
        return result;
    }
    
    end = keywords + count;
    for (key=keywords; key<end; key++) {
        if ((result=insert_keyword(context, key)) != 0) {
            if (result == EINVAL) {
                continue;
            }
            break;
        }
    }

    return result;
}

void word_segment_destroy(WordSegmentContext *context)
{
}

int word_segment_split(WordSegmentContext *context, const string_t *input,
        WordSegmentArray *output)
{
    return 0;
}
