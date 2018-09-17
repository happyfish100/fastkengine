//qa_loader.h

#ifndef _QA_LOADER_H
#define _QA_LOADER_H

#include "fastcommon/common_define.h"
#include "keyword_types.h"

#ifdef __cplusplus
extern "C" {
#endif
    int qa_loader_init(char **filenames, const int count);
    const string_t *keyword_to_similar(string_t *keyword);

#ifdef __cplusplus
}
#endif

#endif
