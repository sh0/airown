/*
 * Airown - UDP layer
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

#ifndef H_PCK_UDP
#define H_PCK_UDP

// Int inc
#include "ao_config.h"
#include "pck_main.h"

// <===> UDP endpoint <========================================================>

class c_ep_udp : public c_ep {
    public:
        // Constructor and destructor
        c_ep_udp(guint16 port);
        c_ep_udp(c_ep_udp* ep_b);
        ~c_ep_udp();
        
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

// <===> UDP layer <===========================================================>

class c_layer_udp : public c_layer {
    public:
        // Constructor and destructor
        c_layer_udp();
        ~c_layer_udp();
        
        // Init and end
        bool init_unpack(GNode* node, GByteArray* data);
        void end();
        
        // Types
        en_layer_type type() { return LAYER_UDP_PCK; }

        // Output
        void str_dump();
        const gchar* str_name();
        const gchar* str_value();
    
        // Endpoints
        st_ep* ep_this() { g_assert(m_active); return &m_ep; }
        GList* ep_list() { g_assert(m_active); return NULL; }
        
    private:
        // Headers
        struct libnet_udp_hdr m_hdr;
        
        // Endpoints
        st_ep m_ep;
};

#endif

