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
    uint32 pl_size;
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
    uint32 proto;
    
    // Ports
    uint16 port_a;
    uint16 port_b;
    
    // Seqencer
    uint32 seq_a;
    uint32 seq_b;
    
    // Packet stack
    GQueue* pck_queue;
    guint32 pck_num;
    guint32 pck_size;
    
    // Timing
    GTimeVal time_first;
    GTimeVal time_last;
    
    // Layer 5
    en_pl_type pl_type;
} st_tcp_con;

#endif

