/* $Id: mod_ip_count.c,v 1.2 2008/11/22 09:10:07 proger Exp $ */

/*
 * Copyright 2004 Ian Holsman,
 * Copyright 2008 Ivan Fitenko
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define APR_WANT_STRFUNC
#include <apr_want.h>
#include <apr_strings.h>
#include <apr_time.h>
#include <apr_network_io.h>

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h" 

#include "apr_memcache.h"
#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#undef PACKAGE_VERSION
#include "mod_ip_count.h"
#define DEFAULT_SERVER "127.0.0.1:11211"
#define DEFURI "/"
#define NOWHITELIST "255.255.255.255"

module AP_MODULE_DECLARE_DATA ip_count_module;

typedef struct {
  char *memcache_servers;
  char *used_uris;
  unsigned int memcache_max_requests;
  unsigned int httpretcode;
  apr_short_interval_time_t memcache_max_time;
  apr_short_interval_time_t memcache_block_time;
  apr_short_interval_time_t rq_latency;
  apr_memcache_t *mc;
  char *whitelisted_ip;
  /* TODO: add config settings for these... */
  /* ... or just get this TODO the hell out of here.*/
  apr_uint32_t min_sockets;
  apr_uint32_t smax_sockets;
  apr_uint32_t max_sockets;
  apr_uint32_t ttl_sockets;
} ip_count_config_rec;

typedef struct {
  int size;	/* container for MaxTime setting */
  int nelts;	/* request counter */
  int posn;	/* positon of current request */
  int lastseenposn; /* position of oldest request */
  int pidaras;	/* blacklist token */
  apr_time_t times[]; /* storage for request times*/
} user_details;


static const char *set_servers(cmd_parms *cmd, void *config, const char *arg1 )
{
    ip_count_config_rec *cfg;
    cfg = ap_get_module_config(cmd->server->module_config, &ip_count_module );
    cfg->memcache_servers = apr_pstrdup( cmd->pool, arg1);
    return NULL;
}

static const char *set_used_uris(cmd_parms *cmd, void *config, const char *arg1 )
{
    ip_count_config_rec *cfg;
    cfg = ap_get_module_config(cmd->server->module_config, &ip_count_module );
    cfg->used_uris = apr_pstrdup( cmd->pool, arg1);
    return NULL;
}

static const char *set_max_time(cmd_parms *cmd, void *config, const char *arg1 )
{
    ip_count_config_rec *cfg;
    cfg = ap_get_module_config(cmd->server->module_config, &ip_count_module );
    cfg->memcache_max_time = apr_time_make( atoi( arg1) ,0);

    return NULL;
}

static const char *set_block_time(cmd_parms *cmd, void *config, const char *arg1 )
{
    ip_count_config_rec *cfg;
    cfg = ap_get_module_config(cmd->server->module_config, &ip_count_module );
    cfg->memcache_block_time = apr_time_make( atoi( arg1) ,0);

    return NULL;
}

static const char *set_max_requests(cmd_parms *cmd, void *config, const char *arg1 )
{
    ip_count_config_rec *cfg;
    cfg = ap_get_module_config(cmd->server->module_config, &ip_count_module );
    cfg->memcache_max_requests = atoi( arg1) - 1;
    return NULL;
}

static const char *set_rq_latency(cmd_parms *cmd, void *config, const char *arg1 )
{
    ip_count_config_rec *cfg;
    cfg = ap_get_module_config(cmd->server->module_config, &ip_count_module );
    cfg->rq_latency = atoi( arg1);
    return NULL;
}


static const char *set_httpretcode(cmd_parms *cmd, void *config, const char *arg1 )
{
    ip_count_config_rec *cfg;
    cfg = ap_get_module_config(cmd->server->module_config, &ip_count_module );
    cfg->httpretcode = atoi( arg1);
    return NULL;
}

static const char *set_whitelisted_ip(cmd_parms *cmd, void *config, const char *arg1 )
{
    ip_count_config_rec *cfg;
    cfg = ap_get_module_config(cmd->server->module_config, &ip_count_module );
    cfg->whitelisted_ip = apr_pstrdup( cmd->pool, arg1);
    return NULL;
}

static void *create_ip_count_server_config(apr_pool_t *p, server_rec *s)
{
    ip_count_config_rec *conf = apr_palloc(p, sizeof(*conf));

    conf->memcache_servers = DEFAULT_SERVER;
    conf->used_uris = DEFURI;
    conf->memcache_max_requests = 50;
    conf->memcache_max_time = apr_time_make(120,0);
    conf->memcache_block_time = apr_time_make(120,0);
    conf->httpretcode = 403;
    conf->min_sockets=2;
    conf->smax_sockets = 5;
    conf->max_sockets = 10;
    conf->ttl_sockets= 600;
    conf->mc = NULL;
    conf->whitelisted_ip= NOWHITELIST;
    conf->rq_latency = 0;
    return conf;
}
 
static void ip_count_child_init(apr_pool_t *p, server_rec *s)
{
    char *serverstring;
    char *serverport;
    char *last;
    int nservers=0;

    apr_status_t rv;
    apr_memcache_server_t *serverrec;

    ip_count_config_rec *conf = ap_get_module_config(s->module_config,
                                                      &ip_count_module);
    /* Find all the servers in the first run to get a total count */
    serverstring = apr_pstrdup(p, conf->memcache_servers);
    serverport = apr_strtok(serverstring, " ", &last);
    while (serverport) {
        nservers++;
        serverport = apr_strtok(NULL," ", &last);
    }    
    
    rv = apr_memcache_create(p, nservers, 0, &conf->mc);

    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s,
                  "apr_memcache_create:unable to initialize memcached");
    }
    serverstring = apr_pstrdup(p, conf->memcache_servers);
    serverport = apr_strtok(serverstring, " ", &last);
    while (serverport) {
       char *server;
       char *scope;
       apr_port_t port;

       rv = apr_parse_addr_port( &server, &scope, &port, serverport, p );
       if ( rv != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s,
                      "apr_memcache_server_create: unable to parse %s (%s)", serverport, conf->memcache_servers );
       }
       if (server == NULL ) {
           server = DEFAULT_SERVER;
       }
       
       rv = apr_memcache_server_create(p, 
                        server, 
                        port,
                        conf->min_sockets,
                        conf->smax_sockets,
                        conf->max_sockets,
                        conf->ttl_sockets,
                        &serverrec);
        if (rv != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s,
                      "apr_memcache_server_create:%s %d", server, port);
	    return DECLINED;
        }
        rv = apr_memcache_add_server(conf->mc, serverrec);
        if (rv != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s,
                      "apr_memcache_add_server:");
        }

       serverport = apr_strtok(NULL," ", &last);
    }
}
/* Checking ID */
static int ip_count_check_auth(request_rec *r)
{
    ip_count_config_rec *conf = ap_get_module_config(r->server->module_config,
                                                      &ip_count_module);
    char *reason = NULL;
    apr_status_t rv;
    user_details *det;
    int i;
    int t_var;
    apr_time_t oldest_time;
    request_rec *rr;
    char datetimestr[APR_RFC822_DATE_LEN];
    apr_time_t *last_seen;
    char *key;
    apr_memcache_t *mc;
    int new=0;
    apr_size_t len;
    apr_uint32_t flags;
    char *result;
    char *uri_samples;
    char* req_uris;
    char* all_whitelisted_ip;
    char* this_whitelisted_ip;
    char* whitelisted_netmask;
    apr_ipsubnet_t* this_subnet;
    char *last;
    int pattern_matched = 0;
    
    if (r->main) {
        return DECLINED;
    }
#ifdef WITH_APACHE24
    key = r->connection->client_ip;
#else
    key = r->connection->remote_ip;
#endif
/*    Use this for debugging
 *    key = r->args;
 */

    if (!key) {
        key = "none";
    }
    mc = conf->mc;

    rv = apr_memcache_getp( mc, r->pool, key, &result, &len, &flags );
    if (rv != APR_SUCCESS && rv != APR_NOTFOUND) {
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, rv, r,
                  "Getting cache key for IP %s", key);
        return DECLINED;
    }

    if (rv == APR_NOTFOUND) {
        det = apr_palloc( r->pool, sizeof(user_details) + sizeof(apr_time_t)* conf->memcache_max_requests );
        det->size = conf->memcache_max_requests;
        det->nelts = 0;
	det->pidaras = 0;
        det->posn = 0;
        det->lastseenposn = 0;
        new = 1;
    } else {
        det = (user_details*)result;
    }

    /*for the configured uris... */
    req_uris = apr_pstrdup(r->pool, conf->used_uris);

    uri_samples = apr_strtok(req_uris, " ",&last);
    do {
        if (strstr(r->uri, uri_samples)) {
            pattern_matched = 1;
            break;
        }
    uri_samples = apr_strtok(NULL, " ",&last);
    } while (uri_samples);

    if (!pattern_matched) {
        return DECLINED;
    }

    /*Process the whitelist, skip the requests mathcing the set criteria*/    
    all_whitelisted_ip = apr_pstrdup(r->pool, conf->whitelisted_ip);
    this_whitelisted_ip = apr_strtok(all_whitelisted_ip, " ",&last);
    do {
	if (!strncmp(this_whitelisted_ip,"env=",4)){
	    if (apr_table_get(r->subprocess_env, (this_whitelisted_ip+4))) {
		return DECLINED;
	    }
	}	    
	if ((whitelisted_netmask = strchr(this_whitelisted_ip, '/'))) {
	    *whitelisted_netmask++ = '\0'; 
	    apr_ipsubnet_create(&this_subnet,this_whitelisted_ip,
		whitelisted_netmask,r->pool);
	} else {
	    apr_ipsubnet_create(&this_subnet,this_whitelisted_ip,NULL,r->pool);
	}
#ifdef WITH_APACHE24
	if (apr_ipsubnet_test(this_subnet,r->connection->client_addr)) {
#else
	if (apr_ipsubnet_test(this_subnet,r->connection->remote_addr)) {
#endif
	    return DECLINED;
	}
	this_whitelisted_ip = apr_strtok(NULL, " ",&last);
    } while (this_whitelisted_ip);

    /* Pass the next request if comes fast enough to be considered the 'dup'*/
    if (conf->rq_latency) {			  
        if ((r->request_time - det->times[ det->posn ]) <= conf->rq_latency) {
	    return DECLINED;
	}
    }

    if (det->pidaras) {
	oldest_time = r->request_time - conf->memcache_block_time;
    } else {
	oldest_time = r->request_time - conf->memcache_max_time;
    }
    
    
    /* remove the requests with expired time */
    last_seen = det->times;
    while  ( det->nelts > 0 && last_seen[ det->lastseenposn ] < oldest_time) {
        det->nelts--;
        det->times[ det->lastseenposn ] = -1;
        det->lastseenposn = ( det->lastseenposn + 1 ) % det->size;
    }

    
    /* ...check if we have gone too far... */
    if ( det->nelts >= det->size || det->nelts >= conf->memcache_max_requests) {
        apr_rfc822_date(datetimestr, det->times[det->lastseenposn] );
        /* ...if so, mark for blacklist... */
        if (!det->pidaras) {
            det->pidaras=1;
            if (conf->memcache_block_time < conf->memcache_max_time) {
                rv = apr_memcache_set( mc, 
			    key, 
			    (char*)det, 
			    sizeof(user_details) + (sizeof(apr_time_t)* det->size),
			    apr_time_sec(conf->memcache_max_time)+600,
			    0);
	    } else {
	        rv = apr_memcache_set( mc, 
			    key, 
		    	    (char*)det, 
			    sizeof(user_details) + (sizeof(apr_time_t)* det->size),
			    apr_time_sec(conf->memcache_block_time)+600,
			    0);
	    }
			
		if (rv) {
    		    ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,                		    "Setting cache key for IP %s failed", key);
		}
	}
    
    /* ... and send the predefined response. */
    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                  "access to %s blocked for IP %s requests started at %s", r->uri, key, datetimestr);
    return conf->httpretcode;
    }
    
    /* now add this one */

    det->nelts++;
    det->posn = ( det->posn + 1 ) % det->size;
    det->times[det->posn ] = r->request_time;

/* 	Debug reporting for each hit 
 *       ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
 *                  "Setting cache key for IP %s OK: seen %d in the last %d seconds", key, det->nelts, apr_time_sec(conf->memcache_max_time));
*/

    /* keep the record around for a bit longer than the max time */
    if (conf->memcache_block_time < conf->memcache_max_time){
        rv = apr_memcache_set( mc, 
		   key, 
		   (char*)det, 
		   sizeof(user_details) + (sizeof(apr_time_t)* det->size),
		   apr_time_sec(conf->memcache_max_time)+600,
		   0);
    } else {
        rv = apr_memcache_set( mc, 
    		   key, 
		   (char*)det, 
		   sizeof(user_details) + (sizeof(apr_time_t)* det->size),
		   apr_time_sec(conf->memcache_block_time)+600,
		   0);
    }
    
    if (rv) {
    ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                  "Setting cache key for IP %s failed", key);
    }

    return DECLINED;
}


static const command_rec ip_count_cmds[] =
{
    AP_INIT_TAKE1("MemCacheServers", set_servers, NULL, RSRC_CONF, 
            "a list of servers running the memcached server (host:port)"),
    AP_INIT_TAKE1("UriList", set_used_uris, NULL, RSRC_CONF, 
            "a list of patterns to match for the uris to operate on"),
    AP_INIT_TAKE1("MemCacheMaxRequests", set_max_requests, NULL, RSRC_CONF, 
            "Max number of requests before failing"),
    AP_INIT_TAKE1("MemCacheMaxTime", set_max_time, NULL, RSRC_CONF,
            "Time period in which the requests have to come (seconds)"),
    AP_INIT_TAKE1("MemCacheBlockTime", set_block_time, NULL, RSRC_CONF,
            "Additional blocking time (seconds)"),
    AP_INIT_TAKE1("Latency", set_rq_latency, NULL, RSRC_CONF,
            "time between requests to consider them a single hit (microseconds)"),
    AP_INIT_TAKE1("HttpResponse", set_httpretcode, NULL, RSRC_CONF,
            "An HTTP code to return in response to a blocked request"),	    
    AP_INIT_TAKE1("MemCacheAllow", set_whitelisted_ip, NULL, RSRC_CONF,
            "IP adresses NOT to perform checks on"),	    
    {NULL}
};

static void register_hooks(apr_pool_t *p)
{

    ap_hook_child_init(ip_count_child_init, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_fixups(ip_count_check_auth, NULL, NULL, APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA ip_count_module =
{
    STANDARD20_MODULE_STUFF,
    NULL,                         /* dir config creater */
    NULL,                         /* dir merger --- default is to override */
    create_ip_count_server_config,/* server config */
    NULL,                         /* merge server config */
    ip_count_cmds,                /* command apr_table_t */
    register_hooks                /* register hooks */
};
