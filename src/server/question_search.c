#include <netdb.h>
#include <unistd.h>
#include <errno.h>
#include "fastcommon/logger.h"
#include "fastcommon/hash.h"
#include "fastcommon/shared_func.h"
#include "server_global.h"
#include "question_search.h"

typedef struct combination_index_array {
    int count;
    uint8_t indexes[MAX_KEYWORDS_ROWS][MAX_KEYWORDS_COUNT];
} CombinationIndexArray;

static CombinationIndexArray index_arrays[MAX_KEYWORDS_COUNT][MAX_KEYWORDS_COUNT];

static void init_combination_index_array4(const int n)
{
    int first, second, third, fourth;
    CombinationIndexArray *index_array;
    uint8_t *indexes;

    index_array = &index_arrays[n - 1][3];
    for (first=0; first<n; first++) {
        for (second=first+1; second<n; second++) {
            for (third=second+1; third<n; third++) {
                for (fourth=third+1; fourth<n; fourth++) {
                    indexes = index_array->indexes[index_array->count++];
                    indexes[0] = first;
                    indexes[1] = second;
                    indexes[2] = third;
                    indexes[3] = fourth;
                }
            }
        }
    }
}

static void init_combination_index_array3(const int n)
{
    int first, second, third;
    CombinationIndexArray *index_array;
    uint8_t *indexes;

    index_array = &index_arrays[n - 1][2];
    for (first=0; first<n; first++) {
        for (second=first+1; second<n; second++) {
            for (third=second+1; third<n; third++) {
                indexes = index_array->indexes[index_array->count++];
                indexes[0] = first;
                indexes[1] = second;
                indexes[2] = third;
            }
        }
    }
}

static void init_combination_index_array2(const int n)
{
    int first, second;
    CombinationIndexArray *index_array;
    uint8_t *indexes;

    index_array = &index_arrays[n - 1][1];
    for (first=0; first<n; first++) {
        for (second=first+1; second<n; second++) {
            indexes = index_array->indexes[index_array->count++];
            indexes[0] = first;
            indexes[1] = second;
        }
    }
}

void init_combination_index_arrays()
{
    int n;

    memset(index_arrays, 0, sizeof(index_arrays));
    for (n=5; n<=MAX_KEYWORDS_COUNT; n++) {
        init_combination_index_array4(n);
    }

    for (n=4; n<=MAX_KEYWORDS_COUNT; n++) {
        init_combination_index_array3(n);
    }

    for (n=3; n<=MAX_KEYWORDS_COUNT; n++) {
        init_combination_index_array2(n);
    }
}

static int compare_question_length(const void *p1, const void *p2)
{
    int result;
    result = ((const QAEntry *)p1)->question->q.len -
        ((const QAEntry *)p2)->question->q.len;
    if (result == 0) {
        return ((const QAEntry *)p2)->question->karray.count -
            ((const QAEntry *)p1)->question->karray.count;
    } else {
        return result;
    }
}

static bool add_answer(QAArray *results, const QAEntry *qa)
{
    int i;

    if (results->count == 0) {
        results->entries[results->count++] = *qa;
    } else if (results->count < MAX_ANSWER_COUNT) {
        for (i=0; i<results->count; i++) {
            if (results->entries[i].answer->id == qa->answer->id) {
                break;
            }
        }
        if (i == results->count) {  //not found
            results->entries[results->count++] = *qa;
            qsort(results->entries, results->count, sizeof(QAEntry),
                    compare_question_length);
        }
    } else {
        if (compare_question_length(qa, results->entries + 0) < 0) {
            return false;
        }
        results->entries[0] = *qa;
        qsort(results->entries, results->count, sizeof(QAEntry),
                compare_question_length);
    }
    return true;
}

static int search_keywords(const KeywordArray *keywords, QAArray *results)
{
    QAEntry qa;
    int result;
    int key_len;

    if (results->count == MAX_ANSWER_COUNT) {
        key_len = keyword_index_key_length(keywords);
        if (key_len < results->entries[0].question->q.len) {
            return EOVERFLOW;
        }
    }

    if ((result=keyword_index_find(&g_server_vars.ki_context,
                    keywords, &qa)) == 0)
    {
        add_answer(results, &qa);
    }

    return result;
}

static void gen_combined_keywords(const KeywordArray *keywords,
        const int cnt, KeywordRecords *records)
{
    int row, col;
    int index;
    uint8_t *indexes;
    CombinationIndexArray *index_array;

    records->count = 0;
    if (cnt >= keywords->count) {
        return;
    }

    if (cnt == 1) {
        int i;
        for (i=0; i<keywords->count; i++) {
            records->rows[i].count = 1;
            records->rows[i].keywords[0] = keywords->keywords[i];
        }
        records->count = keywords->count;
        return;
    }

    index_array = &index_arrays[keywords->count - 1][cnt - 1];
    for (row=0; row<index_array->count; row++) {
        records->rows[row].count = cnt;
        indexes = index_array->indexes[row];
        for (col=0; col<cnt; col++) {
            index = indexes[col];
            records->rows[row].keywords[col] = keywords->keywords[index];
        }
    }
    records->count = index_array->count;
}

static int question_search_all(KeywordRecords *records, QAArray *results)
{
    int result;
    int done_count;
    KeywordArray *p;
    KeywordArray *end;

    done_count = 0;
    end = records->rows + records->count;
    for (p=records->rows; p<end; p++) {
        result = search_keywords(p, results);
        if (result == 0 || result == EOVERFLOW || p->count <= 1) {
            done_count++;
        }
    }

    return done_count;
}

static void print_keyword_records(KeywordRecords *records)
{
    int i, k;
    KeywordArray *p;
    KeywordArray *end;

    printf("keywords count: %d\n", records->count);
    i = 0;
    end = records->rows + records->count;
    for (p=records->rows; p<end; p++) {
        printf("row[%d], keywords: ", i++);
        for (k=0; k<p->count; k++) {
            printf("%.*s ", FC_PRINTF_STAR_STRING_PARAMS(p->keywords[k]));
        }
        printf("\n");
    }
    printf("\n");
}

int question_search(const string_t *question, QAArray *results)
{
    int result;
    WordSegmentArray output;
    KeywordRecords records;
    KeywordArray *p;
    KeywordArray *end;
    bool done[MAX_KEYWORDS_ROWS];
    int done_count;
    int level;
    int i;

    results->count = 0;
    results->match_count = 0;
    if ((result=word_segment_split(question, &output)) != 0) {
        return result;
    }

    print_keyword_records(&output.results);

    done_count = 0;
    i = 0;
    end = output.results.rows + output.results.count;
    for (p=output.results.rows; p<end; p++) {
        result = search_keywords(p, results);
        if (result == 0 || result == EOVERFLOW || p->count <= 1) {
            done[i++] = true;
            done_count++;
        } else {
            done[i++] = false;
        }
    }
    results->match_count += output.results.count;

    level = 1;
    while (done_count < output.results.count) {
        done_count = 0; 
        for (i=0; i<output.results.count; i++) {
            if (done[i]) {
                done_count++;
            } else if (output.results.rows[i].count <= level) {
                done[i]++;
                done_count++;
            } else {
                gen_combined_keywords(output.results.rows + i,
                        output.results.rows[i].count - level, &records);

                printf("C [%d/%d]\n", output.results.rows[i].count - level,
                        output.results.rows[i].count);
                print_keyword_records(&records);

                if (question_search_all(&records, results) > 0) {
                    done[i]++;
                    done_count++;
                }
                results->match_count += records.count;
            }
        }

        level++;
    }

    logInfo("found count: %d, match_count: %d", results->count,
            results->match_count);

    word_segment_free_result(&output);
    return 0;
}
