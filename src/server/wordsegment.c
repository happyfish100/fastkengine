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

static WordSegmentHashEntry *hashtable_insert(WordSegmentContext *context,
        WordSegmentHashTable *htable, const string_t *ch, const bool is_keyword)
{
    WordSegmentHashEntry *hentry;
    unsigned int hash_code;
    unsigned int index;

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

static int next_word(const char **pp, const char *end, string_t *ch)
{
    if (*pp >= end) {
        return ENOENT;
    }

    ch->str = (char *)*pp;
    while (*pp < end &&  ((**pp >= 'a' && **pp <= 'z') ||
                (**pp >= '0' && **pp <= '9')))
    {
        (*pp)++;
    }
    ch->len = (char *)*pp - ch->str;
    if (ch->len > 0) {
        return 0;
    }

    if ((((unsigned char)**pp) & 0xF0) == 0xE0) {  //Chinese character
        ch->len = end - *pp;
        if (ch->len < 3) {
            logError("file: "__FILE__", line: %d, "
                    "invalid Chinese characters length: %d",
                    __LINE__, ch->len);
            *pp += 1;
            return EINVAL;
        }

        if (!(((((unsigned char)ch->str[1]) & 0xC0) == 0x80) &&
                ((((unsigned char)ch->str[2]) & 0xC0) == 0x80)))
        {
            logError("file: "__FILE__", line: %d, "
                    "invalid Chinese characters: %.*s",
                    __LINE__, ch->len, ch->str);
            *pp += 1;
            return EINVAL;
        }

        ch->len = 3;
        *pp += 3;
        return 0;
    } else {
        logWarning("file: "__FILE__", line: %d, "
                "invalid character: %c(0x%02x)",
                __LINE__, **pp, ((unsigned char)**pp) & 0xFF);
        *pp += 1;  //skip unknown char
        return EINVAL;
    }
}

static int insert_keyword(WordSegmentContext *context,
        const string_t *keyword)
{
    string_t ch;
    const char *p;
    const char *end;
    int i;
    WordSegmentHashTable **htable;
    WordSegmentHashEntry *hentry;

    htable = &context->top;
    p = keyword->str;
    end = keyword->str + keyword->len;

    i = 0;
    while (p < end) {
        if (next_word(&p, end, &ch) != 0) {
            continue;
        }

        logInfo("word[%d]: %.*s, last: %d", i, ch.len, ch.str, p == end);

        if ((hentry=insert_char(context, htable, ++i,
                        &ch, p == end)) == 0)
        {
            return ENOMEM;
        }

        htable = &hentry->children;
    }

    return 0;
}

static WordSegmentHashEntry *find_keyword(WordSegmentContext *context,
        const string_t *keyword)
{
    string_t ch;
    const char *p;
    const char *end;
    WordSegmentHashTable **htable;
    WordSegmentHashEntry *hentry;

    hentry = NULL;
    htable = &context->top;
    p = keyword->str;
    end = keyword->str + keyword->len;

    int i = 0;
    while (p < end) {
        if (next_word(&p, end, &ch) != 0) {
            continue;
        }

        logInfo("word[%d]: %.*s, last: %d", i++, ch.len, ch.str, p == end);

        hentry = hashtable_find(*htable, &ch);
        if (hentry == NULL) {
            return NULL;
        }

        htable = &hentry->children;
    }

    return (hentry != NULL && hentry->is_keyword) ? hentry : NULL;
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
                result = 0;
                continue;
            }
            break;
        }
    }

    return result;
}

static void word_segment_normalize(const string_t *input, string_t *output)
{
    unsigned char *p;
    unsigned char *end;
    unsigned char *dest;

    dest = (unsigned char *)output->str;
    p = (unsigned char *)input->str;
    end = (unsigned char *)input->str + input->len;
    while (p < end) {
        if (FC_IS_UPPER_LETTER(*p)) {  //uppercase letter
            *dest++ = *p++ + 32;  //to lowercase
        } else if (*p == '\t' || *p == '\r' || *p == '\n' ||
                *p == '\f' || *p == '\a' || *p == '\b' || *p == '\v')
        {  //space chars
            *dest++ = ' ';
            p++;
        } else if (*p == '-') {
            *dest++ = *p++;
            if (p > (unsigned char *)input->str && p + 1 < end) {
                if (FC_IS_LETTER(*(p-1)) && FC_IS_LETTER(*(p+1))) {
                    dest--;  //ignore -
                }
            }
        } else if ((p + 2 < end) &&
                ((((unsigned char)*p) & 0xF0) == 0xE0) &&
                ((((unsigned char)*(p + 1)) & 0xC0) == 0x80) &&
                ((((unsigned char)*(p + 2)) & 0xC0) == 0x80))
        {
            int old_char;
            old_char = ((*p & 0x1F) << 12) | ((*(p + 1) & 0x3F) << 6) | (*(p + 2) & 0x3F);
            if (old_char == 0x3000) { //blank char
                *dest++ = ' ';
            } else if (old_char >= 0xFF01 && old_char <= 0xFF5E) { //full char
                *dest = old_char - 0xFEE0;
                if (FC_IS_UPPER_LETTER(*dest)) {
                    *dest += 32;
                }
                dest++;
            } else {
                *dest++ = *p;
                *dest++ = *(p + 1);
                *dest++ = *(p + 2);
            }
            p += 3;
        } else {
            *dest++ = *p++;
        }
    }

    output->len = dest - (unsigned char *)output->str;
}

void word_segment_destroy(WordSegmentContext *context)
{
    fast_mblock_destroy(&context->hentry_allocator);
    fast_mblock_destroy(&context->htable_allocator);
    fast_mpool_destroy(&context->string_allocator);
}

int word_segment_split(WordSegmentContext *context, const string_t *input,
        WordSegmentArray *output)
{
    WordSegmentHashEntry *hentry;

    if (input->len <= sizeof(output->buff)) {
        output->holder.str = output->buff;
    } else {
        output->holder.str = (char *)malloc(input->len);
        if (output->holder.str == NULL) {
            logError("file: "__FILE__", line: %d, "
                    "malloc %d bytes fail", __LINE__, input->len);
            return ENOMEM;
        }
    }

    word_segment_normalize(input, &output->holder);
    hentry = find_keyword(context, &output->holder);
    if (hentry != NULL) {
        printf("found %.*s\n", output->holder.len, output->holder.str);
    } else {
        printf("NOT found %.*s\n", output->holder.len, output->holder.str);
    }

    return 0;
}

void word_segment_free_result(WordSegmentArray *array)
{
    if (array->holder.str != NULL && array->holder.str != array->buff) {
        free(array->holder.str);
        array->holder.str = NULL;
    }
}
