#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <sys/types.h>
#include <unistd.h>
#include "fastcommon/logger.h"
#include "fastken/fken_client.h"

typedef struct {
	ngx_http_upstream_conf_t   upstream;
	ngx_uint_t                 headers_hash_max_size;
	ngx_uint_t                 headers_hash_bucket_size;
} ngx_http_fastken_loc_conf_t;

static FKenClient client;

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

static ngx_int_t get_post_content(ngx_http_request_t *r, char * data_buf, int data_size)
{
    size_t content_length;
    ngx_chain_t* bufs;
    ngx_buf_t* buf;
    size_t body_length;
    size_t bytes;

    content_length = r->headers_in.content_length_n;
    ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0, "[get_post_content] [content_length:%d]", content_length); //DEBUG
    if(r->request_body == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "reqeust_body:null");
        return NGX_ERROR;
    }
    if ((int)content_length >= data_size) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "content_length: %d too large exceeds %d",
                (int)content_length, data_size);
        return NGX_ERROR;
    }

    body_length = 0;
    bufs = r->request_body->bufs;
    while (bufs != NULL) {
        buf = bufs->buf;
        bufs = bufs->next;
        bytes = buf->last - buf->pos;
        if (body_length + bytes > content_length) {
            bytes = content_length - body_length;
        }
        memcpy(data_buf + body_length, buf->pos, bytes);
        body_length += bytes;
    }

    if(body_length != content_length) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "get_post_content's body_length != content_length in headers");
        return NGX_ERROR;
    }

    return NGX_OK;
}

static void ngx_http_fastken_body_handler(ngx_http_request_t *r)
{
#define CONTENT_TYPE_STR   "text/plain"
#define CONTENT_TYPE_LEN  (sizeof(CONTENT_TYPE_STR) - 1)

    ngx_int_t rc;
	char content[16 * 1024];
    char buff[1024];
    int len;

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
            "read client request body done");

    memset(content, 0, sizeof(content));
    if (get_post_content(r, content, sizeof(content)) != NGX_OK) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    strcpy(buff, "this is a test");
    len = strlen(buff);

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
