#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <sys/types.h>
#include <unistd.h>
#include "fastcommon/logger.h"
#include "fastcommon/shared_func.h"
#include "fastcommon/http_func.h"
#include "fastcommon/local_ip_func.h"
#include "fastken/fken_client.h"
#include "template.h"

#define MAX_QUESTION_SIZE 64
#define MAX_PARAM_COUNT    5

#define START_MARK_STR  "=[["
#define END_MARK_STR    "]]"
#define START_MARK_LEN  (sizeof(START_MARK_STR) - 1)
#define END_MARK_LEN    (sizeof(END_MARK_STR) - 1)

#define PARAM_NAME_QUESTION_STR  "question"
#define PARAM_NAME_QUESTION_LEN  (sizeof(PARAM_NAME_QUESTION_STR) - 1)

#define PARAM_NAME_ANSWER_STR    "answer"
#define PARAM_NAME_ANSWER_LEN    (sizeof(PARAM_NAME_ANSWER_STR) - 1)

#define PARAM_NAME_DISPLAY_ANSWER_STR  "display_answer"
#define PARAM_NAME_DISPLAY_ANSWER_LEN  (sizeof(PARAM_NAME_DISPLAY_ANSWER_STR) - 1)

#define PARAM_NAME_SERVER_IP_STR  "server_ip"
#define PARAM_NAME_SERVER_IP_LEN  (sizeof(PARAM_NAME_SERVER_IP_STR) - 1)

#define PARAM_NAME_VARS_STR    "vars"
#define PARAM_NAME_VARS_LEN    (sizeof(PARAM_NAME_VARS_STR) - 1)

#define PARAM_NAME_OSNAME_STR  "osname"
#define PARAM_NAME_OSNAME_LEN  (sizeof(PARAM_NAME_OSNAME_STR) - 1)

#define PARAM_NAME_UNAME_STR   "uname"
#define PARAM_NAME_UNAME_LEN   (sizeof(PARAM_NAME_UNAME_STR) - 1)

#define OSNAME_CENTOS_STR  "CentOS"
#define OSNAME_CENTOS_LEN  (sizeof(OSNAME_CENTOS_STR) - 1)

#define OSNAME_UBUNTU_STR  "Ubuntu"
#define OSNAME_UBUNTU_LEN  (sizeof(OSNAME_UBUNTU_STR) - 1)

#define OSNAME_DARWIN_STR  "Darwin"
#define OSNAME_DARWIN_LEN  (sizeof(OSNAME_DARWIN_STR) - 1)

#define UNAME_LINUX_STR    "Linux"
#define UNAME_LINUX_LEN    (sizeof(UNAME_LINUX_STR) - 1)

#define UNAME_DARWIN_STR    OSNAME_DARWIN_STR
#define UNAME_DARWIN_LEN    (sizeof(UNAME_DARWIN_STR) - 1)

#define URI_ROOT_PATH_STR      "/fastken"
#define URI_ROOT_PATH_LEN      (sizeof(URI_ROOT_PATH_STR) - 1)

#define URI_INDEX_HTML_STR      "/index.html"
#define URI_INDEX_HTML_LEN      (sizeof(URI_INDEX_HTML_STR) - 1)

#define URI_SEARCH_UNIX_STR     "/search/unix"
#define URI_SEARCH_UNIX_LEN     (sizeof(URI_SEARCH_UNIX_STR) - 1)

#define EMPTY_RESP_STR   "没有找到你想要的内容，换个问题试试？\n"
#define EMPTY_RESP_LEN   (sizeof(EMPTY_RESP_STR) - 1)

typedef struct {
	ngx_http_upstream_conf_t   upstream;
	ngx_uint_t                 headers_hash_max_size;
	ngx_uint_t                 headers_hash_bucket_size;
} ngx_http_fastken_loc_conf_t;

static FKenClient client;

static string_t start_mark = {START_MARK_STR, START_MARK_LEN};
static string_t end_mark = {END_MARK_STR, END_MARK_LEN};

static string_t param_name_question = {PARAM_NAME_QUESTION_STR,
    PARAM_NAME_QUESTION_LEN};
static string_t param_name_vars = {PARAM_NAME_VARS_STR,
    PARAM_NAME_VARS_LEN};
static string_t param_name_osname = {PARAM_NAME_OSNAME_STR,
    PARAM_NAME_OSNAME_LEN};
static string_t param_name_uname = {PARAM_NAME_UNAME_STR,
    PARAM_NAME_UNAME_LEN};

static string_t uname_linux = {UNAME_LINUX_STR, UNAME_LINUX_LEN};
static string_t uname_darwin = {UNAME_DARWIN_STR, UNAME_DARWIN_LEN};

static string_t local_private_ip = {NULL, 0};

static string_t param_name_answer = {PARAM_NAME_ANSWER_STR,
    PARAM_NAME_ANSWER_LEN};
static string_t param_name_display_answer = {PARAM_NAME_DISPLAY_ANSWER_STR,
    PARAM_NAME_DISPLAY_ANSWER_LEN};
static string_t param_name_server_ip = {PARAM_NAME_SERVER_IP_STR,
    PARAM_NAME_SERVER_IP_LEN};

static string_t string_none = {"none", 4};

static char *ngx_http_fastken_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_int_t ngx_http_fastken_process_init(ngx_cycle_t *cycle);
static void ngx_http_fastken_process_exit(ngx_cycle_t *cycle);

/* Commands */
static ngx_command_t  ngx_http_fastken_commands[] = {
    { ngx_string("ngx_fastken_module"),
      NGX_HTTP_LOC_CONF | NGX_CONF_NOARGS,
      ngx_http_fastken_set,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },
      ngx_null_command
};

static ngx_http_module_t  ngx_http_fastken_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */
    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */
    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */
    NULL,     /* create location configration */
    NULL      /* merge location configration */
};

/* hook */
ngx_module_t  ngx_http_fastken_module = {
    NGX_MODULE_V1,
    &ngx_http_fastken_module_ctx,              /* module context */
    ngx_http_fastken_commands,                 /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    ngx_http_fastken_process_init,             /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    ngx_http_fastken_process_exit,             /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

#include "template.c"

static ngx_int_t fken_send_reply_chunk(ngx_http_request_t *r,
        const bool last_buf, const string_t *buff,
        const bool duplicate)
{
	ngx_buf_t *b;
	ngx_chain_t out;
	ngx_int_t rc;
	u_char *new_buff;

	b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
	if (b == NULL) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
			"ngx_pcalloc fail");
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

    if (duplicate) {
        new_buff = ngx_palloc(r->pool, buff->len);
        if (new_buff == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "ngx_palloc %d bytes fail", buff->len);
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        memcpy(new_buff, buff->str, buff->len);
    } else {
        new_buff = (u_char *)buff->str;
    }

	out.buf = b;
	out.next = NULL;

	b->pos = new_buff;
	b->last = new_buff + buff->len;
	b->memory = 1;
	b->last_in_chain = last_buf;
	b->last_buf = last_buf;

	rc = ngx_http_output_filter(r, &out);
	if (!(rc == NGX_OK || rc == NGX_AGAIN)) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
			"ngx_http_output_filter fail, return code: %d", rc);
	}
    return rc;
}

static ngx_int_t get_post_content(ngx_http_request_t *r, string_t *data,
        const int data_size)
{
    int content_length;
    ngx_chain_t* bufs;
    ngx_buf_t* buf;
    int bytes;

    content_length = r->headers_in.content_length_n;
    if(r->request_body == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "reqeust_body:null");
        return NGX_ERROR;
    }
    if (content_length >= data_size) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "content_length: %d too large exceeds %d",
                (int)content_length, data_size);
        return NGX_ERROR;
    }

    data->len = 0;
    bufs = r->request_body->bufs;
    while (bufs != NULL) {
        buf = bufs->buf;
        bufs = bufs->next;
        bytes = buf->last - buf->pos;
        if (data->len + bytes > content_length) {
            bytes = content_length - data->len;
        }
        memcpy(data->str + data->len, buf->pos, bytes);
        data->len += bytes;
    }

    if (data->len != content_length) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "get_post_content's body_length: %d != "
                "content_length: %d in headers", data->len, content_length);
        return NGX_ERROR;
    }

    *(data->str + data->len) = '\0';
    return NGX_OK;
}

static char *find_end_string(char *str, const int len,
        const string_t *smark, const string_t *emark)
{
    char *p;
    char *end;
    char *pe;
    string_t sub;

    end = str + len;
    p = str;
    while (p < end) {
        if ((pe=strstr(p, emark->str)) == NULL) {
            return NULL;
        }

        sub.str = p;
        sub.len = pe - p;
        if (fc_memmem(&sub, smark) == NULL) {
            return pe;
        }
        p = pe + emark->len;
    }

    return NULL;
}

static int parse_params(string_t *content, key_value_pair_t *params,
        const int max_count, int *param_count)
{

    char *p;
    char *end;
    char *closure;
    char *equal;
    key_value_pair_t *kv_param;

    *param_count = 0;
    if (content->len == 0) {
        return 0;
    }

    end = content->str + content->len;
    p = content->str;
    while (p < end) {
        while (p < end && (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')) {
            p++;
        }
        if (p == end) {
            break;
        }
        if (*param_count >= max_count) {
            logError("file: "__FILE__", line: %d, "
                    "too many parameters, exceeds %d",
                    __LINE__, max_count);
            return ENOSPC;
        }

        kv_param = params + (*param_count);
        kv_param->key.str = p;

        equal = strstr(p, start_mark.str);
        if (equal == NULL) {
            logWarning("file: "__FILE__", line: %d, "
                    "no start mark: %s", __LINE__, start_mark.str);
            return 0;
        }

        kv_param->key.len = equal - p;
        p = equal + start_mark.len;
        kv_param->value.str = p;

        closure = find_end_string(p, end - p, &start_mark, &end_mark);
        if (closure == NULL) {
            logWarning("file: "__FILE__", line: %d, "
                    "no end mark: %s", __LINE__, end_mark.str);
            return 0;
        }

        kv_param->value.len = closure - p; 
        p = closure + end_mark.len;
        (*param_count)++;
    }

    return 0;
}

static string_t *get_param(key_value_pair_t *params,
        const int param_count, const string_t *name)
{
    int i;
    for (i=0; i<param_count; i++) {
        if (fc_string_equal(&params[i].key, name)) {
            return &params[i].value;
        }
    }
    return NULL;
}

static ngx_int_t set_http_header(ngx_http_request_t *r,
    const char *key, const char *low_key, const int key_len,
    char *value, const int value_len)
{
    u_char *new_buff;
    ngx_table_elt_t  *cc;

	new_buff = ngx_palloc(r->pool, (value_len + 1));
	if (new_buff == NULL) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
			"ngx_palloc %d bytes fail", value_len + 1);
		return NGX_ERROR;
	}

    cc = ngx_list_push(&r->headers_out.headers);
    if (cc == NULL)
    {
        return NGX_ERROR;
    }

    memcpy(new_buff, value, value_len);

    cc->hash = 1;
    cc->key.len = key_len;
    cc->key.data = (u_char *)key;
    cc->lowcase_key = (u_char *)low_key;
    cc->value.len = value_len;
    cc->value.data = new_buff;

    return NGX_OK;
}

static inline ngx_int_t set_header_answer_count(ngx_http_request_t *r,
        const int answer_count)
{
#define HEADER_NAME_ANSWER_COUNT_STR "FKen-Answer-Count"
#define HEADER_NAME_ANSWER_COUNT_LEN (sizeof(HEADER_NAME_ANSWER_COUNT_STR) - 1)

    int value_len;
    char buff[20];

    value_len = sprintf(buff, "%d", answer_count);
    return set_http_header(r, HEADER_NAME_ANSWER_COUNT_STR,
            "fken-answer-count", HEADER_NAME_ANSWER_COUNT_LEN,
            buff, value_len);
}

static int format_answer_output(ngx_http_request_t *r,
        FKenAnswerArray *answer_array,
        string_t *output)
{
#define ANSWER_SEPERATOR_STR   "\n==========answer split line==========\n"
#define ANSWER_SEPERATOR_LEN   (sizeof(ANSWER_SEPERATOR_STR) - 1)

#define ANSER_ID_BUFF_SIZE    64

    char id_buffs[FKEN_MAX_ANSWER_COUNT][ANSER_ID_BUFF_SIZE];
    string_t answer_ids[FKEN_MAX_ANSWER_COUNT];
    char *p;
    int i;

    if (answer_array->count > 0) {
        output->len = 0;
        for (i=0; i<answer_array->count; i++) {
            if (i > 0) {
                output->len += ANSWER_SEPERATOR_LEN;
            }

            answer_ids[i].str = id_buffs[i];
            answer_ids[i].len = snprintf(answer_ids[i].str,
                    ANSER_ID_BUFF_SIZE, "question id: %"PRId64"\n\n",
                    answer_array->answers[i].id);
            output->len += answer_ids[i].len + answer_array->
                answers[i].answer.len;
        }

        output->str = (char *)ngx_palloc(r->pool, output->len);
        if (output->str == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "ngx_palloc %d bytes fail", output->len);
            return ENOMEM;
        }

        p = output->str;
        for (i=0; i<answer_array->count; i++) {
            if (i > 0) {
                memcpy(p, ANSWER_SEPERATOR_STR, ANSWER_SEPERATOR_LEN);
                p += ANSWER_SEPERATOR_LEN;
            }
            memcpy(p, answer_ids[i].str, answer_ids[i].len);
            p += answer_ids[i].len;

            memcpy(p, answer_array->answers[i].answer.str,
                    answer_array->answers[i].answer.len);
            p += answer_array->answers[i].answer.len;
        }
    } else {
        output->str = EMPTY_RESP_STR;
        output->len = EMPTY_RESP_LEN;
    }

    return 0;
}

static ngx_int_t send_response(ngx_http_request_t *r,
        FKenAnswerArray *answer_array)
{
#define CONTENT_TYPE_TEXT_STR   "text/plain"
#define CONTENT_TYPE_TEXT_LEN  (sizeof(CONTENT_TYPE_TEXT_STR) - 1)

    string_t output;
    ngx_int_t rc;

    if (format_answer_output(r, answer_array, &output) != 0) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    set_header_answer_count(r, answer_array->count);
    r->headers_out.content_type.len = CONTENT_TYPE_TEXT_LEN;
    r->headers_out.content_type.data = (u_char *)CONTENT_TYPE_TEXT_STR;
    r->headers_out.content_length_n = output.len;
    r->headers_out.status = NGX_HTTP_OK;

    ngx_http_set_content_type(r);

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "ngx_http_send_header fail, return code: %d", rc);
        return rc;
    }

    return fken_send_reply_chunk(r, true, &output, false);
}

static void get_answer_ids_string(FKenAnswerArray *answer_array, char *buff)
{
    int i;
    int len;
    char *p;

    p = buff;
    if (answer_array->count > 0) {
        for (i=0; i<answer_array->count; i++) {
            if (i > 0) {
                *p++ = ' ';
            }

            len = sprintf(p, "%"PRId64, answer_array->answers[i].id);
            p += len;
        }
    } else {
        *p++ = '-';
    }
    *p = '\0';
}

static int fastken_search_do(ngx_http_request_t *r, string_t *question,
        const char *body, key_value_array_t *var_array,
        FKenAnswerArray *answer_array)
{
    int result;
    char answer_ids[32 * FKEN_MAX_ANSWER_COUNT];

    if ((result=fken_client_question_search(&client, question,
                    var_array->kv_pairs, var_array->count, answer_array)) != 0)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "question_search result: %d", result);
        return result;
    }

    get_answer_ids_string(answer_array, answer_ids);
    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
            "answers: %d [%s] %s", answer_array->count,
            answer_ids, body);
    return 0;
}

static void ngx_http_fastken_search_handler(ngx_http_request_t *r)
{
    ngx_int_t rc;
    key_value_pair_t params[FKEN_MAX_CONDITION_COUNT];
    int param_count;
	char body[1 * 1024];
    string_t cont;
    string_t *question;
    string_t *cond;
    FKenAnswerArray answer_array;
    key_value_array_t var_array;
    key_value_pair_t vars[FKEN_MAX_CONDITION_COUNT];
    int var_count;
    //int i;

    cont.str = body;
    cont.len = 0;
    if (get_post_content(r, &cont, sizeof(body)) != NGX_OK) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    parse_params(&cont, params, FKEN_MAX_CONDITION_COUNT, &param_count);

    /*
    logInfo("param count: %d", param_count);
    for (i=0; i<param_count; i++) {
        logInfo("%.*s=%.*s", FC_PRINTF_STAR_STRING_PARAMS(params[i].key),
                FC_PRINTF_STAR_STRING_PARAMS(params[i].value));
    }
    */

    question = get_param(params, param_count, &param_name_question);
    if (question == NULL || question->len == 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "no question in body data");
        ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
        return;
    }
    if (question->len > MAX_QUESTION_SIZE) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "question length: %d exceeds %d",
                question->len, MAX_QUESTION_SIZE);
        ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
        return;
    }

    cond = get_param(params, param_count, &param_name_vars);
    if (cond == NULL) {
        var_count = 0;
    } else {
        parse_params(cond, vars, FKEN_MAX_CONDITION_COUNT,
                &var_count);
        /*
        logInfo("var count: %d", var_count);
        for (int i=0; i<var_count; i++) {
            logInfo("%.*s=%.*s", FC_PRINTF_STAR_STRING_PARAMS(vars[i].key),
                    FC_PRINTF_STAR_STRING_PARAMS(vars[i].value));
        }
        */
    }

    var_array.kv_pairs = vars;
    var_array.count = var_count;
    if (fastken_search_do(r, question, body, &var_array,
                &answer_array) != 0)
    {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    rc = send_response(r, &answer_array);
    ngx_http_finalize_request(r, rc);
}

static void fastken_copy_params_to_kv_array(const KeyValuePairEx *params,
        const int param_count, key_value_array_t *kv_array)
{
    const KeyValuePairEx *p;
    const KeyValuePairEx *end;
    key_value_pair_t *kv;

    end = params + param_count;
    for (p=params,kv=kv_array->kv_pairs; p<end; p++,kv++) {
        FC_SET_STRING_EX(kv->key, p->key, p->key_len);
        FC_SET_STRING_EX(kv->value, p->value, p->value_len);
    }
    kv_array->count = param_count;
}

static inline void fastken_add_param_to_kv_array(key_value_array_t *kv_array,
        string_t *key, string_t *value)
{
    kv_array->kv_pairs[kv_array->count].key = *key;
    kv_array->kv_pairs[kv_array->count].value = *value;
    kv_array->count++;
}

static int fastken_index_format_vars(key_value_array_t *kv_array,
        key_value_array_t *var_array)
{
    string_t *osname;
    string_t *uname;

    osname = get_param(kv_array->kv_pairs, kv_array->count, &param_name_osname);
    if (osname == NULL) {
        return ENOENT;
    }

    if (fc_string_equal2(osname, OSNAME_CENTOS_STR, OSNAME_CENTOS_LEN) ||
            fc_string_equal2(osname, OSNAME_UBUNTU_STR, OSNAME_UBUNTU_LEN))
    {
        uname = &uname_linux;
    } else if (fc_string_equal2(osname, OSNAME_DARWIN_STR, OSNAME_DARWIN_LEN)) {
        uname = &uname_darwin;
    } else {
        uname = &empty_string;
    }

    fastken_add_param_to_kv_array(var_array, &param_name_osname, osname);
    fastken_add_param_to_kv_array(var_array, &param_name_uname, uname);
    return 0;
}

static int fastken_index_search(ngx_http_request_t *r,
        key_value_array_t *kv_array,
        const char *body, string_t *question)
{
    string_t output;
    key_value_array_t var_array;
    key_value_pair_t vars[FKEN_MAX_CONDITION_COUNT];
    FKenAnswerArray answer_array;

    if (question->len > MAX_QUESTION_SIZE) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "question length: %d exceeds %d",
                question->len, MAX_QUESTION_SIZE);
        return NGX_HTTP_BAD_REQUEST;
    }

    var_array.kv_pairs = vars;
    var_array.count = 0;
    if (fastken_index_format_vars(kv_array, &var_array) != 0) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (fastken_search_do(r, question, body, &var_array,
                &answer_array) != 0)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (format_answer_output(r, &answer_array, &output) != 0) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    fastken_add_param_to_kv_array(kv_array, &param_name_answer, &output);
    return NGX_OK;
}

static ngx_int_t fastken_index_do(ngx_http_request_t *r, const char *body,
        const KeyValuePairEx *params, const int param_count)
{
#define CONTENT_TYPE_HTML_STR   "text/html; charset=UTF-8"
#define CONTENT_TYPE_HTML_LEN  (sizeof(CONTENT_TYPE_HTML_STR) - 1)

	ngx_int_t rc;
    string_t output;
    key_value_pair_t kvs[MAX_PARAM_COUNT + 8];
    key_value_array_t kv_array;
    string_t *question;

    logInfo("param_count: %d", param_count);
    {
        int i;
        for (i=0; i<param_count; i++) {
            logInfo("%s=%.*s", params[i].key, params[i].value_len, params[i].value);
        }
    }

    kv_array.kv_pairs = kvs;
    fastken_copy_params_to_kv_array(params, param_count, &kv_array);

    question = get_param(kv_array.kv_pairs, param_count, &param_name_question);
    if (question != NULL && question->len > 0) {
        if ((rc=fastken_index_search(r, &kv_array, body, question)) != NGX_OK) {
            return rc;
        }
    } else {
        fastken_add_param_to_kv_array(&kv_array, &param_name_display_answer,
                &string_none);
    }

    fastken_add_param_to_kv_array(&kv_array, &param_name_server_ip,
            &local_private_ip);

    if (render_index_template(r, &kv_array, &output) != 0) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    r->headers_out.content_type.len = CONTENT_TYPE_HTML_LEN;
    r->headers_out.content_type.data = (u_char *)CONTENT_TYPE_HTML_STR;
    r->headers_out.content_length_n = output.len;
    r->headers_out.status = NGX_HTTP_OK;

    ngx_http_set_content_type(r);

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "ngx_http_send_header fail, return code: %d", rc);
        return rc;
    }

    return fken_send_reply_chunk(r, true, &output, false);
}

static ngx_int_t ngx_http_fastken_index_handler(ngx_http_request_t *r)
{
    int param_count;
	char body[1024];
    string_t cont;
    KeyValuePairEx params[MAX_PARAM_COUNT];

    cont.str = body;
    if ((r->method & NGX_HTTP_POST) != 0) {
        cont.len = 0;
        if (get_post_content(r, &cont, sizeof(body)) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    } else {
        if (r->args.len >= sizeof(body)) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "args length: %d exceeds %d",
                    (int)r->args.len, (int)sizeof(body));
            return NGX_HTTP_BAD_REQUEST;
        }

        cont.len = r->args.len;
        memcpy(cont.str, r->args.data, cont.len);
        *(cont.str + cont.len) = '\0';
    }

    param_count = http_parse_url_params(cont.str, cont.len,
        params, MAX_PARAM_COUNT);
    return fastken_index_do(r, body, params, param_count);
}

static void ngx_http_fastken_index_post_handler(ngx_http_request_t *r)
{
    ngx_int_t rc;
    rc = ngx_http_fastken_index_handler(r);
    ngx_http_finalize_request(r, rc);
}

static inline ngx_int_t ngx_http_fastken_read_body(ngx_http_request_t *r,
        ngx_http_client_body_handler_pt post_handler)
{
	ngx_int_t rc;

    rc = ngx_http_read_client_request_body(r, post_handler);
    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }
    return NGX_DONE;
}

static ngx_int_t ngx_http_fastken_handler(ngx_http_request_t *r)
{
    string_t relative_path;

    if (!(r->uri.len >= URI_ROOT_PATH_LEN && memcmp(r->uri.data,
                    URI_ROOT_PATH_STR, URI_ROOT_PATH_LEN) == 0))
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "invalid uri: %s", r->uri.data);
        return NGX_HTTP_BAD_REQUEST;
    }

    relative_path.str = (char *)r->uri.data + URI_ROOT_PATH_LEN;
    relative_path.len = r->uri.len - URI_ROOT_PATH_LEN;

    if (fc_string_equal2(&relative_path, URI_INDEX_HTML_STR,
                URI_INDEX_HTML_LEN) || (relative_path.len == 0) ||
            fc_string_equal2(&relative_path, "/", 1))
    {
        logInfo("method: %d, uri: %.*s(HOME PAGE)", (int)r->method, (int)r->uri.len, r->uri.data);
        logInfo("method: %d, args: %.*s", (int)r->method, (int)r->args.len, r->args.data);

        if ((r->method & NGX_HTTP_POST) != 0) {
            return ngx_http_fastken_read_body(r, ngx_http_fastken_index_post_handler);
        } else {
            return ngx_http_fastken_index_handler(r);
        }
    }

    logInfo("uri: %.*s(%d)", (int)r->uri.len, r->uri.data, (int)r->uri.len);

    if (fc_string_equal2(&relative_path, URI_SEARCH_UNIX_STR,
                URI_SEARCH_UNIX_LEN))
    {
        if (!(r->method & (NGX_HTTP_POST))) {
            return NGX_HTTP_NOT_ALLOWED;
        }

        return ngx_http_fastken_read_body(r, ngx_http_fastken_search_handler);
    } else {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "invalid uri: %s", r->uri.data);
        return NGX_HTTP_BAD_REQUEST;
    }
}

static char *ngx_http_fastken_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_http_core_loc_conf_t *clcf = ngx_http_conf_get_module_loc_conf(cf,
						ngx_http_core_module);

	// register hanlder
	clcf->handler = ngx_http_fastken_handler;

	fprintf(stderr, "ngx_http_fastken_set pid: %d\n", getpid());
    return NGX_CONF_OK;
}

static ngx_int_t ngx_http_fastken_process_init(ngx_cycle_t *cycle)
{
#ifndef CLIENT_CONF_FILENAME
#define CLIENT_CONF_FILENAME  "/etc/fken/client.conf"
#endif
	int result;

	fprintf(stderr, "ngx_http_fastken_process_init pid=%d, "
            "client config filename: %s\n", getpid(), CLIENT_CONF_FILENAME);
    log_init();
	if ((result=fken_client_init(&client, CLIENT_CONF_FILENAME)) != 0) {
		return NGX_ERROR;
	}

    if ((result=load_index_template()) != 0) {
		return NGX_ERROR;
    }

    local_private_ip.str = (char *)get_first_local_ip();
    local_private_ip.len = strlen(local_private_ip.str);

    logInfo("index_temp_node_array.count: %d", index_temp_node_array.count);

	return NGX_OK;
}

static void ngx_http_fastken_process_exit(ngx_cycle_t *cycle)
{
    fprintf(stderr, "ngx_http_fastken_process_exit pid=%d\n", getpid());
    return;
}
