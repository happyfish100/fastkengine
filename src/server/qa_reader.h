//qa_reader.h

#ifndef _QA_READER_H
#define _QA_READER_H

#include "fastcommon/common_define.h"
#include "fastcommon/fast_mpool.h"
#include "fastcommon/fast_buffer.h"
#include "keyword_types.h"

typedef struct qa_reader_entry {
    KeywordRecords questions;
    AnswerEntry answer;
} QAReaderEntry;

typedef struct qa_reader_context {
    const char *filename;
    string_t file_content;
    struct fast_mpool_man *mpool;
    FastBuffer *buffer;
    char *p;
    char *end;
    int64_t base_id;
} QAReaderContext;

#ifdef __cplusplus
extern "C" {
#endif
    int qa_reader_init(QAReaderContext *context, struct fast_mpool_man *mpool,
            FastBuffer *buffer, const char *filename);

    void qa_reader_destroy(QAReaderContext *context);

    int qa_reader_next(QAReaderContext *context, QAReaderEntry *entry);

    int compare_key_value_pair(const key_value_pair_t *kv1,
            const key_value_pair_t *kv2);

#ifdef __cplusplus
}
#endif

#endif
