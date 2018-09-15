#include <netdb.h>
#include <unistd.h>
#include <errno.h>
#include "fastcommon/logger.h"
#include "fastcommon/hash.h"
#include "fastcommon/shared_func.h"
#include "keyword_hashtable.h"
#include "server_global.h"
#include "wordsegment.h"

int word_segment_next_word(const char **pp, const char *end, string_t *ch)
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

static int word_segment_output(CombineKeywordInfo *keywords, const int count,
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
        if (hentry->similar.len == 0) {  \
            break; \
        } \
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
        kinfo->karray.keywords[0] = hentry->similar;      \
        kinfo->karray.count = 1;  \
        kinfo++; \
    } while (0)

static int word_segment_do_split(WordSegmentArray *output)
{
#define MAX_KEYWORDS  (MAX_KEYWORDS_COUNT * MAX_KEYWORDS_COUNT)
#define MAX_KEYWORD_CHARS   16   //Note: an english word as a char

    string_t word;
    string_t chrs[MAX_KEYWORD_CHARS];
    CombineKeywordInfo keywords[MAX_KEYWORDS];
    CombineKeywordInfo *kinfo;
    KeywordHashEntry *hentry;
    const char *p;
    const char *end;
    const char *start;
    const char *save_point;
    int chr_count;
    int key_count;

    kinfo = keywords;
    p = output->holder.str;
    end = output->holder.str + output->holder.len;
    while (p < end) {
        start = p;
        if (word_segment_next_word(&p, end, &word) != 0) {
            continue;
        }

        chrs[0] = word;
        chr_count = 1;
        save_point = p;

        while (true) {
            logInfo("finding: %.*s(%d), chr_count: %d",
                    (int)(p - start), start, (int)(p - start), chr_count);
            if ((hentry=keyword_hashtable_find_ex(&g_server_vars.kh_context,
                            chrs, chr_count)) != NULL)
            {
                SET_KEYWORD_INFO(kinfo, hentry);
            } else {
                break;
            }

            while (p < end && *p == ' ') {
                p++;
            }
            if (word_segment_next_word(&p, end, &word) != 0) {
                break;
            }

            if (chr_count == MAX_KEYWORD_CHARS) {
                logWarning("file: "__FILE__", line: %d, "
                        "too many keyword chars exceed %d, keywords: %.*s",
                        __LINE__, MAX_KEYWORD_CHARS, (int)(p - start), start);
                break;
            }
            chrs[chr_count++] = word;
        }

        p = save_point;  //rewind
    }

    key_count = kinfo - keywords;
    logInfo("found keyword key_count: %d", key_count);
    return word_segment_output(keywords, key_count, output);
}

int word_segment_split(const string_t *input, WordSegmentArray *output)
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
    return word_segment_do_split(output);
}

void word_segment_free_result(WordSegmentArray *array)
{
    if (array->holder.str != NULL && array->holder.str != array->buff) {
        free(array->holder.str);
        array->holder.str = NULL;
    }
}
