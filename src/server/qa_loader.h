//qa_loader.h

#ifndef _QA_LOADER_H
#define _QA_LOADER_H

#include "fastcommon/common_define.h"
#include "keyword_types.h"

#ifdef __cplusplus
extern "C" {
#endif
    int qa_loader_init(const char **filenames, const int count);

#ifdef __cplusplus
}
#endif

#endif
