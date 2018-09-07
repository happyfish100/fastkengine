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

static int next_word(const char **pp, const char *end, string_t *ch,
        bool *is_chinese)
{
    ch->str = (char *)*pp;
    if (*pp >= end) {
        return ENOENT;
    }

    while ((*pp < end) &&  (FC_IS_LOWER_LETTER(**pp) ||
                FC_IS_DIGITAL(**pp)))
    {
        (*pp)++;
    }
    ch->len = (char *)*pp - ch->str;
    if (ch->len > 0) {
        *is_chinese = false;
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
        *is_chinese = true;
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
        const string_t *keyword, bool *pure_chinese, int *char_count)
{
    string_t ch;
    const char *p;
    const char *end;
    int i;
    bool is_chinese;
    WordSegmentHashTable **htable;
    WordSegmentHashEntry *hentry;

    *pure_chinese = true;
    *char_count = 0;
    htable = &context->top;
    p = keyword->str;
    end = keyword->str + keyword->len;

    i = 0;
    while (p < end) {
        if (next_word(&p, end, &ch, &is_chinese) != 0) {
            continue;
        }

        if (is_chinese) {
            (*char_count)++;
        } else {
            *pure_chinese = false;
            *char_count += ch.len;
        }

        logInfo("word[%d]: %.*s, last: %d, is_chinese: %d",
                i, ch.len, ch.str, p == end, is_chinese);

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
    bool is_chinese;

    htable = &context->top;
    p = keyword->str;
    end = keyword->str + keyword->len;

    int i = 0;
    while (p < end) {
        if (next_word(&p, end, &ch, &is_chinese) != 0) {
            continue;
        }

        logInfo("finding WORD[%d]: %.*s, last: %d, is_chinese: %d",
                i++, ch.len, ch.str, p == end, is_chinese);

        hentry = hashtable_find(*htable, &ch);
        if (hentry == NULL) {
            return NULL;
        }

        if (p == end) {
            return hentry->is_keyword ? hentry : NULL;
        }

        htable = &hentry->children;
        if (*htable == NULL) {
            return NULL;
        }
    }

    return NULL;
}

int word_segment_init(WordSegmentContext *context, const int top_capacity,
        const string_t *keywords, const int count)
{
    const string_t *key;
    const string_t *end;
    int result;
    int char_count;
    bool pure_chinese;

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
    
    context->max_chinese_chars = 0;
    end = keywords + count;
    for (key=keywords; key<end; key++) {
        if ((result=insert_keyword(context, key, &pure_chinese,
                        &char_count)) == 0)
        {
            if (pure_chinese && char_count > context->max_chinese_chars) {
                context->max_chinese_chars = char_count;
            }
        } else {
            if (result == EINVAL) {
                result = 0;
                continue;
            }
            break;
        }
    }

    logInfo("max_chinese_chars: %d", context->max_chinese_chars);
    return result;
}

static void remove_spaces_after_chinese(string_t *input)
{
    unsigned char *p;
    unsigned char *end;
    unsigned char *dest;

    dest = (unsigned char *)input->str;
    p = (unsigned char *)input->str;
    end = (unsigned char *)input->str + input->len;
    while (p < end) {
        if ((p + 2 < end) &&
                ((((unsigned char)*p) & 0xF0) == 0xE0) &&
                ((((unsigned char)*(p + 1)) & 0xC0) == 0x80) &&
                ((((unsigned char)*(p + 2)) & 0xC0) == 0x80))
        {
            *dest++ = *p++;
            *dest++ = *p++;
            *dest++ = *p++;
            while (p < end && *p == ' ') {
                p++;
            }
        } else {
            *dest++ = *p++;
        }
    }
    input->len = dest - (unsigned char *)input->str;
}

void word_segment_normalize(const string_t *input, string_t *output)
{
    unsigned char *p;
    unsigned char *end;
    unsigned char *dest;
    int space_count;
    int chinses_count;

    space_count = chinses_count = 0;
    dest = (unsigned char *)output->str;
    p = (unsigned char *)input->str;
    end = (unsigned char *)input->str + input->len;
    while (p < end) {
        if (FC_IS_UPPER_LETTER(*p)) {  //uppercase letter
            *dest++ = *p++ + 32;  //to lowercase
        } else if (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n' ||
                *p == '\f' || *p == '\a' || *p == '\b' || *p == '\v')
        {  //space chars
            *dest++ = ' ';
            space_count++;
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
                space_count++;
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
                chinses_count++;
            }
            p += 3;
        } else {
            *dest++ = *p++;
        }
    }

    output->len = dest - (unsigned char *)output->str;
    if (space_count > 0 && chinses_count > 0) {
        remove_spaces_after_chinese(output);
    }
}

void word_segment_destroy(WordSegmentContext *context)
{
    fast_mblock_destroy(&context->hentry_allocator);
    fast_mblock_destroy(&context->htable_allocator);
    fast_mpool_destroy(&context->string_allocator);
}

static int compare_offset(const void *p1, const void *p2)
{
    return ((CombineKeywordInfo *)p1)->offset.start -
        ((CombineKeywordInfo *)p2)->offset.start;
}

static int compare_string(const void *p1, const void *p2)
{
    return fc_string_compare((const string_t *)p1, (const string_t *)p2);
}

static bool combo_keywords_equals(CombineKeywordInfo *combo1,
        CombineKeywordInfo *combo2)
{
    int i;
    if (combo1->count != combo2->count) {
        return false;
    }

    if (!(combo1->offset.start == combo2->offset.start &&
                combo1->offset.end == combo2->offset.end))
    {
        return false;
    }

    for (i=0; i<combo1->count; i++) {
        if (!fc_string_equal(combo1->keywords + i, combo2->keywords + i)) {
            return false;
        }
    }
    return true;
}

static bool combo_keywords_exist(ComboKeywordGroup *group,
        CombineKeywordInfo *combo_keyword)
{
    int i;

    for (i=0; i<group->count; i++) {
        if (combo_keywords_equals(group->rows + i, combo_keyword)) {
            return true;
        }
    }
    return false;
}

static void combine_nearby_two_keywords(ComboKeywordGroup *group,
        ComboKeywordGroup *combined, ComboKeywordGroup *single)
{
    int i, k;
    int keyword_count;
    CombineKeywordInfo *row;
    CombineKeywordInfo overlapps[MAX_KEYWORDS_COUNT];

    keyword_count = combined->count;
    memcpy(overlapps, combined->rows,
            sizeof(CombineKeywordInfo) * keyword_count);

    combined->count = 0;

    for (i=0; i<keyword_count; i++) {
        for (k=0; k<single->count; k++) {
            if (!combo_keyword_is_overlapp(overlapps + i,
                        single->rows + k))
            {
                if (combined->count >= MAX_KEYWORDS_COUNT) {
                    logWarning("file: "__FILE__", line: %d, "
                            "keywords exceeds %d",
                            __LINE__, MAX_KEYWORDS_COUNT);
                    break;
                }

                row = combined->rows + combined->count++;
                *row = overlapps[i];
                combo_keywords_append(row, single->rows + k);
                break;
            }
        }

        if (k == single->count) {
            if (group->count < MAX_KEYWORDS_COUNT) {
                if (!combo_keywords_exist(group, overlapps + i)) {
                    group->rows[group->count++] = overlapps[i];
                }
            } else {
                logWarning("file: "__FILE__", line: %d, "
                        "keywords exceeds %d",
                        __LINE__, MAX_KEYWORDS_COUNT);
            }
        }
    }
}

static void word_segment_combine_nearby_keywords(ComboKeywordGroup *group)
{
    int i, k;
    bool matched[MAX_KEYWORDS_COUNT];
    ComboKeywordGroup combined;
    ComboKeywordGroup single;
    CombineKeywordInfo *row;

    single = *group;
    combined.count = 0;
    group->count = 0;
    memset(matched, 0, sizeof(matched));

    for (i=0; i<single.count; i++) {
        for (k=i+1; k<single.count; k++) {
            if (!combo_keyword_is_overlapp(single.rows + i,
                        single.rows + k))
            {
                matched[i] = matched[k] = true;
                row = combined.rows + combined.count++;
                *row = single.rows[i];
                combo_keywords_append(row, single.rows + k);
                break;
            }
        }

        if (!matched[i]) {
            if (group->count < MAX_KEYWORDS_COUNT) {
                group->rows[group->count++] = single.rows[i];
            } else {
                logWarning("file: "__FILE__", line: %d, "
                        "keywords exceeds %d",
                        __LINE__, MAX_KEYWORDS_COUNT);
            }
        }
    }

    logInfo("combined count ===== %d", combined.count);
    while (combined.count > 0) {
        combine_nearby_two_keywords(group, &combined, &single);
        logInfo("combined count ===== %d", combined.count);
    }
}

static int word_segment_output(WordSegmentContext *context,
        CombineKeywordInfo *keywords, const int count,
        WordSegmentArray *output)
{
    CombineKeywordInfo *p;
    CombineKeywordInfo *end;
    KeywordIterator iterator;
    ComboKeywordGroup *group;
    int end_offset;
    int end_offset1;
    int end_offset2;
    int max_end_offset;
    int min_end_offset;
    int i;

    if (count == 0) {
        output->result.count = 0;
        return ENOENT;
    } else if (count == 1) {
        output->result.count = 1;
        output->result.rows[0] = *keywords;
        return 0;
    }

    qsort(keywords, count, sizeof(CombineKeywordInfo), compare_offset);

    logInfo("keyword count: %d", count);
    for (i=0; i<count; i++) {
        logInfo("offset: %d, %.*s(%d)", keywords[i].offset.start,
                keywords[i].keywords[0].len, keywords[i].keywords[0].str,
                keywords[i].keywords[0].len);
    }

    p = keywords;
    end = keywords + count;

    memset(&iterator, 0, sizeof(iterator));
    group = iterator.groups - 1;

    while (p < end) {
        group++;
        if (group - iterator.groups >= MAX_KEYWORDS_COUNT) {
            logWarning("file: "__FILE__", line: %d, "
                    "keywords group exceeds %d",
                    __LINE__, MAX_KEYWORDS_COUNT);
            break;
        }

        group->rows[group->count++] = *p; //first keyword
        end_offset1 = p->offset.end;
        p++;
        if (p == end) {
            break;
        }

        if (p->offset.start >= end_offset1) {  //next group
            continue;
        }

        group->rows[group->count++] = *p; //second keyword
        end_offset2 = p->offset.end;
        p++;

        if (end_offset1 > end_offset2) {
            max_end_offset = end_offset1;
            min_end_offset = end_offset2;
        } else {
            max_end_offset = end_offset2;
            min_end_offset = end_offset1;
        }

        while (p < end && (p->offset.start < min_end_offset ||
                    p->offset.end <= max_end_offset))
        {
            end_offset = p->offset.end;
            if (end_offset < min_end_offset) {
                min_end_offset = end_offset;
            } else if (end_offset > max_end_offset) {
                max_end_offset = end_offset;
            }

            if (group->count < MAX_KEYWORDS_COUNT) {
                group->rows[group->count++] = *p;
            } else {
                logWarning("file: "__FILE__", line: %d, "
                        "keywords exceeds %d",
                        __LINE__, MAX_KEYWORDS_COUNT);
            }
            p++;
        }

        if (group->count > 2) {
            word_segment_combine_nearby_keywords(group);
        }
    }

    iterator.count = (group - iterator.groups) + 1;
    logInfo("iterator.count: %d", iterator.count);

    for (i=0; i<iterator.count; i++) {
        int k;
        int m;

        logInfo("group[%d], count: %d", i, iterator.groups[i].count);

        for (k=0; k<iterator.groups[i].count; k++) {
            printf("start: %d, end: %d, keywords: ",
                    iterator.groups[i].rows[k].offset.start,
                    iterator.groups[i].rows[k].offset.end);
            for (m=0; m<iterator.groups[i].rows[k].count; m++) {
                printf("%.*s, ", iterator.groups[i].rows[k].keywords[m].len,
                        iterator.groups[i].rows[k].keywords[m].str);
            }
            printf("\n");
        }
    }

    keyword_iterator_expand(&iterator, &output->result);

    printf("\nkeywords count: %d\n", output->result.count);
    for (i=0; i<output->result.count; i++) {
        int k;

        /*
        qsort(output->result.rows[i].keywords,
                output->result.rows[i].count,
                sizeof(string_t), compare_string);
                */

        printf("row[%d] start: %d, end: %d, keywords: ", i,
                output->result.rows[i].offset.start,
                output->result.rows[i].offset.end);
        for (k=0; k<output->result.rows[i].count; k++) {
            printf("%.*s ", FC_PRINTF_STAR_STRING_PARAMS(output->result.rows[i].keywords[k]));
        }
        printf("\n");
    }

    //TODO DO filter!!!

    return 0;
}

#define SET_KEYWORD_INFO(kinfo) \
    do {  \
        if (kinfo - keywords >= MAX_KEYWORDS) {  \
            logWarning("file: "__FILE__", line: %d, " \
                    "too many keywords exceeds %d",   \
                    __LINE__, MAX_KEYWORDS);          \
            p = save_point = end;  \
            break;  \
        } \
        logInfo("FOUND kEYWORD: %.*s", (int)(p - start), start);     \
        kinfo->offset.start = start - output->holder.str; \
        kinfo->offset.end = p - output->holder.str;       \
        kinfo->keywords[0].str = (char *)start;           \
        kinfo->keywords[0].len = p - start;               \
        kinfo->count = 1;  \
        kinfo++; \
    } while (0)

static int word_segment_do_split(WordSegmentContext *context,
        WordSegmentArray *output)
{
#define MAX_KEYWORDS  (MAX_KEYWORDS_COUNT * MAX_KEYWORDS_COUNT)
    string_t word;
    string_t keyword;
    CombineKeywordInfo keywords[MAX_KEYWORDS];
    CombineKeywordInfo *kinfo;
    int count;
    const char *p;
    const char *end;
    const char *start;
    const char *save_point;
    int i;
    int chinese_chars;
    bool is_chinese;

    kinfo = keywords;
    p = output->holder.str;
    end = output->holder.str + output->holder.len;
    i = 0;
    while (p < end) {
        start = p;
        if (next_word(&p, end, &word, &is_chinese) != 0) {
            continue;
        }
        if (!is_chinese) {
            if (find_keyword(context, &word) != NULL) {
                SET_KEYWORD_INFO(kinfo);
            }
            continue;
        }

        keyword.str = (char *)(p - word.len);
        keyword.len = 0;
        chinese_chars = 1;
        save_point = p;
        while (true) {
            keyword.len += word.len;
            logInfo("finding: %.*s(%d)", keyword.len, keyword.str, keyword.len);
            if (find_keyword(context, &keyword) != NULL) {
                SET_KEYWORD_INFO(kinfo);
            }

            if (++chinese_chars > context->max_chinese_chars) {
                break;
            }

            while (p < end && *p == ' ') {
                p++;
            }
            if (next_word(&p, end, &word, &is_chinese) != 0) {
                break;
            }
            if (!is_chinese) {
                break;
            }
        }

        p = save_point;  //rewind
    }

    count = kinfo - keywords;
    logInfo("found keyword count: %d", count);
    return word_segment_output(context, keywords, count, output);
}

int word_segment_split(WordSegmentContext *context, const string_t *input,
        WordSegmentArray *output)
{
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
    return word_segment_do_split(context, output);
}

void word_segment_free_result(WordSegmentArray *array)
{
    if (array->holder.str != NULL && array->holder.str != array->buff) {
        free(array->holder.str);
        array->holder.str = NULL;
    }
}
