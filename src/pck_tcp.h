/*
 * Airown - TCP layer
 *
 * Copyright (C) 2010-2011 sh0 <sh0@yutani.ee>
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

#ifndef H_PCK_TCP
#define H_PCK_TCP

// Int inc
#include "ao_config.h"
#include "pck_main.h"

// <===> TCP endpoint <========================================================>

class c_ep_tcp : public c_ep {
    public:
        // Constructor and destructor
        c_ep_tcp(guint16 port);
        c_ep_tcp(c_ep_tcp* ep_b);
        ~c_ep_tcp();
        
        // Types
        guint cast();
        
        // Compare
        bool cmp(c_ep* ep_b);
        
        // Output
        void str_dump();
        const gchar* str_name();
        const gchar* str_value();
    
    private:
        // Port
        guint m_port;
        gchar* m_str;
};

// <===> TCP layer <===========================================================>

// TCP timestamp
typedef struct {
    guint32 time_a;
    guint32 time_b;
} __attribute__ ((packed)) st_tcp_timestamp;

class c_layer_tcp : public c_layer {
    public:
        // Constructor and destructor
        c_layer_tcp();
        ~c_layer_tcp();
        
        // Init and end
        bool init_unpack(GNode* node, GByteArray* data);
        void end();
        
        // Types
        en_layer_type type() { return LAYER_TCP_PCK; }

        // Output
        void str_dump();
        const gchar* str_name();
        const gchar* str_value();
    
        // Endpoints
        st_ep* ep_this() { g_assert(m_active); return &m_ep; }
        GList* ep_list() { g_assert(m_active); return NULL; }
        
    private:
        // Headers
        struct libnet_tcp_hdr m_hdr;
        st_tcp_timestamp m_ts;
        
        // Endpoints
        st_ep m_ep;
};

#endif

