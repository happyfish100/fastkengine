//question_search.h

#ifndef _QUESTION_SEARCH_H
#define _QUESTION_SEARCH_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "fastcommon/common_define.h"
#include "fastcommon/fast_mblock.h"
#include "fastcommon/fast_mpool.h"
#include "keyword_types.h"

#ifdef __cplusplus
extern "C" {
#endif

    void init_combination_index_arrays();
    int question_search(const string_t *question, const key_value_array_t *vars,
            QASearchResultArray *results);

#ifdef __cplusplus
}
#endif

#endif
