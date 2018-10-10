//template.h

#ifndef _FASTKEN_TEMPLATE_H
#define _FASTKEN_TEMPLATE_H

#define TEMPLATE_NODE_TYPE_STRING    1
#define TEMPLATE_NODE_TYPE_VARIABLE  2

typedef struct template_node {
    int type;
    string_t value;
} TemplateNode;

typedef struct template_node_array {
    TemplateNode *nodes;
    int count;
    int alloc;
} TemplateNodeArray;

static TemplateNodeArray index_temp_node_array = {NULL, 0, 0};
static string_t index_file_content = {NULL, 0};
static string_t empty_string = {NULL, 0};

#endif

