#include <netdb.h>
#include <unistd.h>
#include <errno.h>
#include "fastcommon/logger.h"
#include "fastcommon/hash.h"
#include "fastcommon/shared_func.h"
#include "wordsegment.h"

static int hashtable_init(WordSegmentContext *context, const int capacity)
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
    bytes = sizeof(struct word_segment_hash_entry *) * context->htable.capacity;
    context->htable.buckets = (struct word_segment_hash_entry **)malloc(bytes);
    if (context->htable.buckets == NULL) {
        logError("file: "__FILE__", line: %d, "
                "malloc %d bytes fail", __LINE__, bytes);
        return ENOMEM;
    }

    memset(context->htable.buckets, 0, bytes);
    return 0;
}

static WordSegmentHashEntry *hashtable_find(WordSegmentContext *context,
        const string_t *keyword)
{
    WordSegmentHashEntry *current;
    unsigned int hash_code;
    unsigned int index;

    hash_code = simple_hash(keyword->str, keyword->len);
    index = hash_code % context->htable.capacity;
    current = context->htable.buckets[index];
    while (current != NULL) {
        if (fc_string_equal(&current->keyword, keyword)) {
            return current;
        }
        current = current->next;
    }

    return NULL;
}

static WordSegmentHashEntry *hashtable_insert(WordSegmentContext *context,
        const string_t *keyword, const string_t *similar)
{
    WordSegmentHashEntry *hentry;
    unsigned int hash_code;
    int result;
    unsigned int index;

    hentry = (WordSegmentHashEntry *)fast_mblock_alloc_object(
            &context->hentry_allocator);
    if (hentry == NULL) {
        logError("file: "__FILE__", line: %d, "
                "alloc hash entry fail", __LINE__);
        return NULL;
    }

    if ((result=fast_mpool_strdup2(&context->string_allocator,
                    &hentry->keyword, keyword)) != 0)
    {
        return NULL;
    }

    if (fc_string_equal(keyword, similar)) {
        hentry->similar = hentry->keyword;
    } else {
        if ((result=fast_mpool_strdup2(&context->string_allocator,
                        &hentry->similar, similar)) != 0)
        {
            return NULL;
        }
    }

    hash_code = simple_hash(keyword->str, keyword->len);
    index = hash_code % context->htable.capacity;
    hentry->next = context->htable.buckets[index];
    context->htable.buckets[index] = hentry;
    return hentry;
}

static int insert_hentry(WordSegmentContext *context,
        const string_t *keyword, const string_t *similar,
        const bool is_kv_same)
{
    WordSegmentHashEntry *hentry;
    int result;

    hentry = hashtable_find(context, keyword);
    if (hentry != NULL) {
        if (is_kv_same) {
            return EEXIST;
        }

        if (fc_string_equal(&hentry->keyword, &hentry->similar)) {
            if ((result=fast_mpool_strdup2(&context->string_allocator,
                            &hentry->similar, similar)) != 0)
            {
                return result;
            }
            return 0;
        }

        logWarning("file: "__FILE__", line: %d, "
                "keyword %.*s already exists, similar is: %.*s",
                __LINE__, keyword->len, keyword->str,
                hentry->similar.len, hentry->similar.str);
        return EEXIST;
    }

    return hashtable_insert(context, keyword, similar) != NULL ? 0 : ENOMEM;
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

static int keyword_char_count(const string_t *keyword, bool *pure_chinese)
{
    string_t ch;
    const char *p;
    const char *end;
    int char_count;
    int i = 0;
    bool is_chinese;

    *pure_chinese = true;
    char_count = 0;
    p = keyword->str;
    end = keyword->str + keyword->len;

    while (p < end) {
        if (next_word(&p, end, &ch, &is_chinese) != 0) {
            continue;
        }

        if (is_chinese) {
            char_count++;
        } else {
            *pure_chinese = false;
            char_count += ch.len;
        }

        logInfo("word[%d]: %.*s, last: %d, is_chinese: %d",
                i++, ch.len, ch.str, p == end, is_chinese);
    }

    return char_count;
}

static int similar_keywords_init(WordSegmentContext *context,
        const SimilarKeywordsInput *similars)
{
#define MAX_SIMILAR_WORDS_COUNT   128

    char **line;
    char **end;
    string_t word;
    string_t similar;
    char *keywords[MAX_SIMILAR_WORDS_COUNT];
    int n;
    int i;
    int result = 0;

    end = similars->lines + similars->count;
    for (line=similars->lines; line<end; line++) {
        if (**line == '\0') {
            continue;
        }
        n = splitEx(*line, similars->seperator, keywords, MAX_SIMILAR_WORDS_COUNT);
        if (n <= 1) {
            logWarning("file: "__FILE__", line: %d, "
                    "invalid similar keywords: %s", __LINE__, *line);
            continue;
        }

        FC_SET_STRING(similar, keywords[0]);
        for (i=1; i<n; i++) {
            FC_SET_STRING(word, keywords[i]);
            if (!fc_string_equal(&word, &similar)) {
                result = insert_hentry(context, &word, &similar, false);
                if (result != 0) {
                    break;
                }
            }
        }
    }

    return result;
}

int word_segment_add_keywords(WordSegmentContext *context,
        const KeywordArray *keywords)
{
    int result;
    const string_t *key;
    const string_t *end;
    int char_count;
    bool pure_chinese;

    result = 0;
    end = keywords->keywords + keywords->count;
    for (key=keywords->keywords; key<end; key++) {
        if ((result=insert_hentry(context, key, key, true)) == 0) {
            char_count = keyword_char_count(key, &pure_chinese);
            if (pure_chinese && char_count > context->max_chinese_chars) {
                context->max_chinese_chars = char_count;
            }
        } else {
            if (result == EINVAL || result == EEXIST) {
                result = 0;
                continue;
            }
            break;
        }
    }

    logInfo("max_chinese_chars: %d", context->max_chinese_chars);
    return result;
}

int word_segment_init(WordSegmentContext *context, const int capacity,
        const SimilarKeywordsInput *similars)
{
    int result;

    if ((result=fast_mblock_init_ex(&context->hentry_allocator,
            sizeof(WordSegmentHashEntry), 102400, NULL, false)) != 0)
    {
        return result;
    }
    
    if ((result=fast_mpool_init(&context->string_allocator, 0, 32)) != 0) {
        return result;
    }
    
    if ((result=hashtable_init(context, capacity)) != 0) {
        return result;
    }

    context->max_chinese_chars = 0;
    return similar_keywords_init(context, similars);
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
    fast_mpool_destroy(&context->string_allocator);
}

static int compare_offset(const void *p1, const void *p2)
{
    return ((CombineKeywordInfo *)p1)->offset.start -
        ((CombineKeywordInfo *)p2)->offset.start;
}

static int compare_combo_keywords(const void *p1, const void *p2)
{
    int i;
    int result;
    const CombineKeywordInfo *key1;
    const CombineKeywordInfo *key2;

    key1 = (const CombineKeywordInfo *)p1;
    key2 = (const CombineKeywordInfo *)p2;
    if (key1->karray.count < key2->karray.count) {
        return 1;
    } else if (key1->karray.count > key2->karray.count) {
        return -1;
    } else {
        for (i=0; i<key1->karray.count; i++) {
            if ((result=fc_string_compare(key1->karray.keywords + i,
                            key2->karray.keywords + i)) != 0)
            {
                return result;
            }
        }
    }

    return 0;
}

static bool combo_keywords_equals(CombineKeywordInfo *combo1,
        CombineKeywordInfo *combo2)
{
    int i;
    if (combo1->karray.count != combo2->karray.count) {
        return false;
    }

    if (!(combo1->offset.start == combo2->offset.start &&
                combo1->offset.end == combo2->offset.end))
    {
        return false;
    }

    for (i=0; i<combo1->karray.count; i++) {
        if (!fc_string_equal(combo1->karray.keywords + i,
                    combo2->karray.keywords + i))
        {
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

void keywords_unique(KeywordArray *karray)
{
    string_t *p;
    string_t *end;
    string_t *dest;

    end = karray->keywords + karray->count;
    p = dest = karray->keywords + 1;
    while (p < end) {
        if (fc_string_compare(p, p - 1) != 0) {
            if (dest != p) {
                *dest = *p;
            }
            dest++;
        }
        p++;
    }

    karray->count = dest - karray->keywords;
}

static void sorted_keyword_records_unique(KeywordRecords *results)
{
    KeywordArray *p;
    KeywordArray *end;

    end = results->rows + results->count;
    for (p=results->rows; p<end; p++) {
        if (p->count > 1) {
            keywords_unique(p);
        }
    }
}

void keyword_records_unique(KeywordRecords *results)
{
    KeywordArray *p;
    KeywordArray *end;

    end = results->rows + results->count;
    for (p=results->rows; p<end; p++) {
        if (p->count > 1) {
            qsort(p->keywords, p->count, sizeof(string_t),
                    (int (*)(const void *p1, const void *p2))fc_string_compare);
            keywords_unique(p);
        }
    }
}

static void output_results_unique(ComboKeywordGroup *combo_results,
        KeywordRecords *results)
{
    CombineKeywordInfo *p;
    CombineKeywordInfo *end;
    KeywordArray *dest;

    end = combo_results->rows + combo_results->count;
    for (p=combo_results->rows; p<end; p++) {
        qsort(p->karray.keywords,
                p->karray.count,
                sizeof(string_t),
                (int (*)(const void *p1, const void *p2))fc_string_compare);
    }

    qsort(combo_results->rows, combo_results->count,
            sizeof(CombineKeywordInfo), compare_combo_keywords);

    dest = results->rows;
    *dest++ = combo_results->rows[0].karray;
    p = combo_results->rows + 1;
    while (p < end) {
        if (compare_combo_keywords(p, p - 1) != 0) {
            *dest++ = p->karray;
        }
        p++;
    }
    results->count = dest - results->rows;
    sorted_keyword_records_unique(results);
}

static int word_segment_output(WordSegmentContext *context,
        CombineKeywordInfo *keywords, const int count,
        WordSegmentArray *output)
{
    CombineKeywordInfo *p;
    CombineKeywordInfo *end;
    KeywordIterator iterator;
    ComboKeywordGroup *group;
    ComboKeywordGroup combo_results;
    int end_offset;
    int end_offset1;
    int end_offset2;
    int max_end_offset;
    int min_end_offset;
    int i;

    if (count == 0) {
        output->results.count = 0;
        return ENOENT;
    } else if (count == 1) {
        output->results.count = 1;
        output->results.rows[0] = keywords->karray;
        return 0;
    }

    qsort(keywords, count, sizeof(CombineKeywordInfo), compare_offset);

    logInfo("keyword count: %d", count);
    for (i=0; i<count; i++) {
        logInfo("offset: %d, %.*s(%d)", keywords[i].offset.start,
                FC_PRINTF_STAR_STRING_PARAMS(keywords[i].karray.keywords[0]),
                keywords[i].karray.keywords[0].len);
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
            for (m=0; m<iterator.groups[i].rows[k].karray.count; m++) {
                printf("%.*s, ", FC_PRINTF_STAR_STRING_PARAMS(
                            iterator.groups[i].rows[k].karray.keywords[m]));
            }
            printf("\n");
        }
    }

    keyword_iterator_expand(&iterator, &combo_results);
    output_results_unique(&combo_results, &output->results);

    return 0;
}

#define SET_KEYWORD_INFO(kinfo, hentry) \
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
        kinfo->karray.keywords[0] = hentry->similar;             \
        kinfo->karray.count = 1;  \
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
    WordSegmentHashEntry *hentry;
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
            if ((hentry=hashtable_find(context, &word)) != NULL) {
                SET_KEYWORD_INFO(kinfo, hentry);
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
            if ((hentry=hashtable_find(context, &keyword)) != NULL) {
                SET_KEYWORD_INFO(kinfo, hentry);
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
