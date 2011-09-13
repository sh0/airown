/*
 * Airown - IPv6 packets
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

#ifndef H_PCK_IPV6
#define H_PCK_IPV6

// Int inc
#include "ao_config.h"
#include "pck_main.h"

// <===> IPv6 endpoint <=======================================================>

class c_ep_ipv6 : public c_ep {
    public:
        // Constructor and destructor
        c_ep_ipv6(struct libnet_in6_addr* addr);
        c_ep_ipv6(c_ep_ipv6* ep_b);
        ~c_ep_ipv6();
        
        // Types
        guint cast();
        
        // Compare
        bool cmp(c_ep* ep_b);
        
        // Output
        void str_dump();
        const gchar* str_name();
        const gchar* str_value();
    
    private:
        // Address
        guint m_cast;
        struct libnet_in6_addr m_addr;
        gchar* m_str;
};

// <===> IPv6 layer <==========================================================>

class c_layer_ipv6 : public c_layer {
    public:
        // Constructor and destructor
        c_layer_ipv6();
        ~c_layer_ipv6();

        // Init and end
        bool init_unpack(GNode* node, GByteArray* data);
        void end();
                
        // Types
        en_layer_type type() { return LAYER_IPV6_PCK; }
        
        // Output
        void str_dump();
        const gchar* str_name();
        const gchar* str_value();
    
        // Endpoints
        st_ep* ep_this() { g_assert(m_active); return &m_ep; }
        GList* ep_list() { g_assert(m_active); return NULL; }
        
    private:
        // Headers
        struct libnet_ipv6_hdr m_hdr;
        
        // Endpoints
        st_ep m_ep;
};

#endif

