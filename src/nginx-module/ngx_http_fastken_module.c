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

/*
static void *ngx_http_fastken_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_fastken_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);

static ngx_str_t  ngx_http_proxy_hide_headers[] = {
	ngx_string("Date"),
	ngx_string("Server"),
	ngx_string("X-Pad"),
	ngx_string("X-Accel-Expires"),
	ngx_string("X-Accel-Redirect"),
	ngx_string("X-Accel-Limit-Rate"),
	ngx_string("X-Accel-Buffering"),
	ngx_string("X-Accel-Charset"),
	ngx_null_string
};
*/

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
    NULL,  //ngx_http_fastken_init,                 /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,    /* create location configration */
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

#if 0
static void fken_output_headers(ngx_http_request_t *r)
{
	ngx_int_t rc;

    /*
		if (pResponse->content_type != NULL)
		{
		r->headers_out.content_type.len = strlen(pResponse->content_type);
		r->headers_out.content_type.data = (u_char *)pResponse->content_type;
		}

		r->headers_out.content_length_n = pResponse->content_length;
		r->headers_out.last_modified_time = pResponse->last_modified;
        */

	ngx_http_set_content_type(r);

    /*
	r->headers_out.status = pResponse->status;
    if (pResponse->content_length <= 0)
    {
        r->header_only = 1;
    }
    */

	rc = ngx_http_send_header(r);
	if (rc == NGX_ERROR || rc > NGX_OK)
	{
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
			"ngx_http_send_header fail, return code=%d", rc);
		return;
	}
}

static int fken_send_reply_chunk(void *arg, const bool last_buf, \
		const char *buff, const int size)
{
	ngx_http_request_t *r;
	ngx_buf_t *b;
	ngx_chain_t out;
	ngx_int_t rc;
	u_char *new_buff;

	r = (ngx_http_request_t *)arg;

	b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
	if (b == NULL)
	{
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
			"ngx_pcalloc fail");
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	new_buff = ngx_palloc(r->pool, sizeof(u_char) * size);
	if (new_buff == NULL)
	{
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
	if (rc == NGX_OK || rc == NGX_AGAIN)
	{
		return 0;
	}
	else
	{
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
			"ngx_http_output_filter fail, return code: %d", rc);
		return rc;
	}
}
#endif

static void ngx_http_fastken_body_handler(ngx_http_request_t *r)
{
    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
            "read client request body done");
    ngx_http_finalize_request(r, NGX_OK);
}

/*
static ngx_int_t ngx_http_fastken_handler1(ngx_http_request_t *r)
{
    logInfo("file: "__FILE__", line: %d, length: %d, request_body: %p",
            __LINE__, (int)(r->headers_in.content_length_n),
            r->request_body);
    return NGX_OK;
}
*/

static ngx_int_t get_post_content(ngx_http_request_t *r, char * data_buf, int data_size)
{
    size_t content_length;

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

    ngx_chain_t* bufs = r->request_body->bufs;
    ngx_buf_t* buf = NULL;
    size_t body_length = 0;
    size_t buf_length;
    while(bufs) {
        buf = bufs->buf;
        bufs = bufs->next;
        buf_length = buf->last - buf->pos;
        if(body_length + buf_length > content_length) {
            memcpy(data_buf + body_length, buf->pos, content_length - body_length);
            body_length = content_length;
            break;
        }
        memcpy(data_buf + body_length, buf->pos, buf->last - buf->pos);
        body_length += buf->last - buf->pos;
    }

    if(body_length != content_length) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "get_post_content's body_length != content_length in headers");
        return NGX_ERROR;
    }

    return NGX_OK;
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

    if (r->request_body->rest == 0) {
        memset(url, 0, sizeof(url));
        get_post_content(r, url, sizeof(url));
        logInfo("body: %s", url);
    }

    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }
    return NGX_DONE;

    /*
	rc = ngx_http_discard_request_body(r);
	if (rc != NGX_OK && rc != NGX_AGAIN)
	{
		return rc;
	}
    */

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

    /*
	memset(&context, 0, sizeof(context));
	context.output_headers = fken_output_headers;
	context.send_reply_chunk = fken_send_reply_chunk;
    */

	/*
	ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
			"args=%*s, uri=%*s", r->args.len, r->args.data,
			r->uri.len, r->uri.data);
	*/

	return NGX_OK;
}

static char *ngx_http_fastken_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_http_core_loc_conf_t *clcf = ngx_http_conf_get_module_loc_conf(cf,
						ngx_http_core_module);

	// register hanlder
	clcf->handler = ngx_http_fastken_handler;
    //ngx_conf_set_str_slot(cf, cmd, conf);

	fprintf(stderr, "ngx_http_fastken_set pid: %d\n", getpid());

    return NGX_CONF_OK;
}
/*
static ngx_int_t ngx_http_fastken_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_CONTENT_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_fastken_handler;

    return NGX_OK;
}
*/

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

#if 0
static void *ngx_http_fastken_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_fastken_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_fastken_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->upstream.connect_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.send_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.read_timeout = NGX_CONF_UNSET_MSEC;

    conf->upstream.buffer_size = NGX_CONF_UNSET_SIZE;

    conf->upstream.hide_headers = NGX_CONF_UNSET_PTR;
    conf->upstream.pass_headers = NGX_CONF_UNSET_PTR;

    /* the hardcoded values */
    conf->upstream.cyclic_temp_file = 0;
    conf->upstream.buffering = 0;
    conf->upstream.ignore_client_abort = 0;
    conf->upstream.send_lowat = 0;
    conf->upstream.bufs.num = 0;
    conf->upstream.busy_buffers_size = 0;
    conf->upstream.max_temp_file_size = 0;
    conf->upstream.temp_file_write_size = 0;
    conf->upstream.intercept_errors = 1;
    conf->upstream.intercept_404 = 1;
    conf->upstream.pass_request_headers = 0;
    conf->upstream.pass_request_body = 0;

    conf->headers_hash_max_size = NGX_CONF_UNSET_UINT;
    conf->headers_hash_bucket_size = NGX_CONF_UNSET_UINT;

    return conf;
}

static char * ngx_http_fastken_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_hash_init_t             hash;
    ngx_http_fastken_loc_conf_t *prev = parent;
    ngx_http_fastken_loc_conf_t *conf = child;

    ngx_conf_merge_msec_value(conf->upstream.connect_timeout,
                              prev->upstream.connect_timeout, 60000);

    ngx_conf_merge_msec_value(conf->upstream.send_timeout,
                              prev->upstream.send_timeout, 60000);

    ngx_conf_merge_msec_value(conf->upstream.read_timeout,
                              prev->upstream.read_timeout, 60000);

    ngx_conf_merge_size_value(conf->upstream.buffer_size,
                              prev->upstream.buffer_size,
                              (size_t) ngx_pagesize);

    ngx_conf_merge_bitmask_value(conf->upstream.next_upstream,
                              prev->upstream.next_upstream,
                              (NGX_CONF_BITMASK_SET
                               |NGX_HTTP_UPSTREAM_FT_ERROR
                               |NGX_HTTP_UPSTREAM_FT_TIMEOUT));

    if (conf->upstream.next_upstream & NGX_HTTP_UPSTREAM_FT_OFF) {
        conf->upstream.next_upstream = NGX_CONF_BITMASK_SET
                                       |NGX_HTTP_UPSTREAM_FT_OFF;
    }

    if (conf->upstream.upstream == NULL) {
        conf->upstream.upstream = prev->upstream.upstream;
    }

    ngx_conf_merge_uint_value(conf->headers_hash_max_size,
                              prev->headers_hash_max_size, 512);

    ngx_conf_merge_uint_value(conf->headers_hash_bucket_size,
                              prev->headers_hash_bucket_size, 64);
    conf->headers_hash_bucket_size = ngx_align(conf->headers_hash_bucket_size,
                                               ngx_cacheline_size);

    hash.max_size = conf->headers_hash_max_size;
    hash.bucket_size = conf->headers_hash_bucket_size;
    hash.name = "proxy_headers_hash";

    if (ngx_http_upstream_hide_headers_hash(cf, &conf->upstream,
            &prev->upstream, ngx_http_proxy_hide_headers, &hash)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}
#endif
