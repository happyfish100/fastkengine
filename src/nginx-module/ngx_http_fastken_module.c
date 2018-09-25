#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <sys/types.h>
#include <unistd.h>
#include "fastcommon/logger.h"
#include "fastcommon/shared_func.h"
#include "fastken/fken_client.h"

#define START_MARK_STR  "=[["
#define END_MARK_STR    "]]"
#define START_MARK_LEN  (sizeof(START_MARK_STR) - 1)
#define END_MARK_LEN    (sizeof(END_MARK_STR) - 1)

#define PARAM_NAME_QUESTION_STR  "question"
#define PARAM_NAME_QUESTION_LEN  (sizeof(PARAM_NAME_QUESTION_STR) - 1)

#define PARAM_NAME_CONDITIONS_STR  "conditions"
#define PARAM_NAME_CONDITIONS_LEN  (sizeof(PARAM_NAME_CONDITIONS_STR) - 1)

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
static string_t param_name_conditions = {PARAM_NAME_CONDITIONS_STR,
    PARAM_NAME_CONDITIONS_LEN};

static char *ngx_http_fastken_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
//static ngx_int_t ngx_http_fastken_init(ngx_conf_t *cf);

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

static ngx_int_t fken_send_reply_chunk(ngx_http_request_t *r,
        const bool last_buf, const char *buff, const int size)
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

	new_buff = ngx_palloc(r->pool, sizeof(u_char) * size);
	if (new_buff == NULL) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
			"ngx_palloc fail");
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	out.buf = b;
	out.next = NULL;

	memcpy(new_buff, buff, size);

	b->pos = (u_char *)new_buff;
	b->last = (u_char *)new_buff + size;
	b->memory = 1;
	b->last_in_chain = last_buf;
	b->last_buf = last_buf;

	/*
	ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
			"ngx_http_output_filter, sent: %d", r->connection->sent);
	*/

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
    ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0, "[get_post_content] [content_length:%d]", content_length); //DEBUG
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

static void ngx_http_fastken_body_handler(ngx_http_request_t *r)
{
#define CONTENT_TYPE_STR   "text/plain"
#define CONTENT_TYPE_LEN  (sizeof(CONTENT_TYPE_STR) - 1)

    ngx_int_t rc;
    key_value_pair_t params[FKEN_MAX_CONDITION_COUNT];
    int param_count;
	char content[16 * 1024];
    string_t cont;
    char *buff;
    int len;
    string_t *question;
    string_t *cond;
    FKenAnswerArray answer_array;
    key_value_pair_t conditions[FKEN_MAX_CONDITION_COUNT];
    int condition_count;
    int result;
    int i;

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
            "read client request body done");

    cont.str = content;
    cont.len = 0;
    memset(content, 0, sizeof(content));
    if (get_post_content(r, &cont, sizeof(content)) != NGX_OK) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    parse_params(&cont, params, FKEN_MAX_CONDITION_COUNT, &param_count);
    logInfo("param count: %d", param_count);
    for (i=0; i<param_count; i++) {
        logInfo("%.*s=%.*s", FC_PRINTF_STAR_STRING_PARAMS(params[i].key),
                FC_PRINTF_STAR_STRING_PARAMS(params[i].value));
    }

    question = get_param(params, param_count, &param_name_question);
    if (question == NULL) {
        ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
        return;
    }

    cond = get_param(params, param_count, &param_name_conditions);
    if (cond == NULL) {
        condition_count = 0;
    } else {
        parse_params(cond, conditions, FKEN_MAX_CONDITION_COUNT,
                &condition_count);
        logInfo("condition count: %d", condition_count);
        for (i=0; i<condition_count; i++) {
            logInfo("%.*s=%.*s", FC_PRINTF_STAR_STRING_PARAMS(conditions[i].key),
                    FC_PRINTF_STAR_STRING_PARAMS(conditions[i].value));
        }
    }

    if ((result=fken_client_question_search(&client, question,
                    conditions, condition_count, &answer_array)) != 0)
    {
        fprintf(stderr, "result: %d", result);
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    fprintf(stderr, "answer count: %d\n", answer_array.count);
    for (i=0; i<answer_array.count; i++) {
        fprintf(stderr, "%d. answer========\n", i + 1);
        fprintf(stderr, "id: %"PRId64"\n", answer_array.answers[i].id);
        fprintf(stderr, "%.*s\n", FC_PRINTF_STAR_STRING_PARAMS(answer_array.answers[i].answer));
    }

    if (answer_array.count > 0) {
        buff = answer_array.answers[0].answer.str;
        len = answer_array.answers[0].answer.len;
    } else {
        buff = strdup("this is a test");
        len = strlen(buff);
    }

    r->headers_out.content_type.len = CONTENT_TYPE_LEN;
    r->headers_out.content_type.data = (u_char *)CONTENT_TYPE_STR;
    r->headers_out.content_length_n = len;
    r->headers_out.status = NGX_HTTP_OK;

	ngx_http_set_content_type(r);

    logInfo("body:: %.*s [%d]", 256, content, (int)strlen(content));

	rc = ngx_http_send_header(r);
	if (rc == NGX_ERROR || rc > NGX_OK)
	{
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
			"ngx_http_send_header fail, return code=%d", rc);
		return;
	}

    rc = fken_send_reply_chunk(r, true, buff, len);
    ngx_http_finalize_request(r, rc);
}

static ngx_int_t ngx_http_fastken_handler(ngx_http_request_t *r)
{
	ngx_int_t rc;
	char url[4096];
	char *p;

    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "file: "__FILE__", line: %d, NGX_DONE: %d, NGX_HTTP_SPECIAL_RESPONSE: %d, length: %d",
            __LINE__, NGX_DONE, NGX_HTTP_SPECIAL_RESPONSE, (int)(r->headers_in.content_length_n));

	if (!(r->method & (NGX_HTTP_POST))) {
		return NGX_HTTP_NOT_ALLOWED;
	}

    rc = ngx_http_read_client_request_body(r, ngx_http_fastken_body_handler);

    logInfo("post_handler: %p, equal: %d", r->request_body->post_handler,
            r->request_body->post_handler == ngx_http_fastken_body_handler);
    logInfo("rest: %d", (int)r->request_body->rest);

    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }
    return NGX_DONE;

	if (r->uri.len + r->args.len + 1 >= sizeof(url))
	{
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
			"url too long, exceeds %d bytes!", (int)sizeof(url));
		return NGX_HTTP_BAD_REQUEST;
	}

	p = url;
	memcpy(p, r->uri.data, r->uri.len);
	p += r->uri.len;
	if (r->args.len > 0)
	{
		*p++ = '?';
		memcpy(p, r->args.data, r->args.len);
		p += r->args.len;
	}
	*p = '\0';

	return NGX_OK;
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

	return NGX_OK;
}

static void ngx_http_fastken_process_exit(ngx_cycle_t *cycle)
{
    fprintf(stderr, "ngx_http_fastken_process_exit pid=%d\n", getpid());
    return;
}
