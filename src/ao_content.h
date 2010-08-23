/*
 * Airown - content
 *
 * Copyright (C) 2010 sh0 <sh0@yutani.ee>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef H_AO_CONTENT
#define H_AO_CONTENT

// Int inc
#include "ao_config.h"
#include "ao_main.h"

// HTTP payload
typedef enum {
    AO_HTTP_REQ_GET = 0,
    AO_HTTP_REQ_POST
} en_http_req;

typedef struct {
    // Request
    en_http_req req_type;
    gchar* req_url;
    // Headers
    gchar* hdr_accept;
    gchar* hdr_host;
    gchar* hdr_referer;
    gchar* hdr_content_type;
    gint32 hdr_content_length;
    gchar* hdr_range;
    gchar* hdr_authorization;
} st_ctx_http;

// Payload type
typedef enum {
    AO_PL_NONE = 0,
    AO_PL_HTTP
} en_pl_type;

// TCP packet structure
typedef struct {
    // General
    gboolean dir_send;
    // Payload
    guint32 pl_size;
    guint8* pl_data;
} st_tcp_pck;

// TCP connection structure
typedef struct {
    // Connection
    gint con_syn;
    gint con_fin;
    gint con_rst;

    // Addresses
    union {
        struct in_addr ip4_a;
        struct in6_addr ip6_a;
    };
    union {
        struct in_addr ip4_b;
        struct in6_addr ip6_b;
    };
    guint32 proto;
    
    // Ports
    guint16 port_a;
    guint16 port_b;
    
    // Seqencer
    guint32 seq_a;
    guint32 seq_b;
    
    // Packet stack
    GQueue* pck_queue;
    guint32 pck_num;
    guint32 pck_total_size;
    guint32 pck_buf_size;
    
    // Timing
    GTimeVal time_first;
    GTimeVal time_last;
    
    // Layer 5
    en_pl_type pl_type;
    
    // Log
    FILE* log_file;
} st_tcp_con;

// Functions
gint ctx_tcp_cmp(gconstpointer ptr_a, gconstpointer ptr_b);
void ctx_tcp_syn(st_ao_packet* pck);
void ctx_tcp_fin(st_tcp_con* con);
void ctx_tcp_pck(st_tcp_con* con, st_ao_packet* pck);
void ctx_tcp_pl(st_tcp_con* con);
void ctx_tcp_proc(st_ao_packet* pck);
void ctx_tcp_audit();

#endif

