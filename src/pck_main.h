/*
 * Airown - Packets
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

#ifndef H_AO_PACKET
#define H_AO_PACKET

// Int inc
#include "ao_config.h"
#include "drv_main.h"

// Endpoint casts
typedef enum {
    EP_CAST_NONE = 0,
    EP_CAST_UNICAST,
    EP_CAST_MULTICAST,
    EP_CAST_BROADCAST,
    EP_CAST_LOOPBACK
} en_ep_cast;

// Endpoint class
class c_ep {
    public:
        // Destructor
        virtual ~c_ep() { }
        
        // Types
        virtual guint cast() = 0;
        
        // Comparing
        virtual bool cmp(c_ep* ep) = 0;
        
        // Output
        virtual void str_dump() = 0;
        virtual const gchar* str_name() = 0;
        virtual const gchar* str_value() = 0;
};

// Endpoint struct
typedef struct {
    c_ep* src;
    c_ep* dst;
    c_ep* net;
} st_ep;

// Layer types
typedef enum {
    LAYER_HW_PCK = 0,
    LAYER_RADIOTAP_PCK,
    LAYER_80211_PCK,
    LAYER_8023_PCK,
    LAYER_IPV4_PCK,
    LAYER_IPV4_ASM,
    LAYER_IPV6_PCK,
    LAYER_ARP_PCK,
    LAYER_TCP_PCK,
    LAYER_TCP_ASM,
    LAYER_UDP_PCK,
    LAYER_UDP_ASM
} en_layer_type;

// Layer class
class c_layer {
    public:
        // Destructor
        virtual ~c_layer() { }
        
        // Types
        virtual en_layer_type type() = 0;
        
        // Output
        virtual void str_dump() = 0;
        virtual const gchar* str_name() = 0;
        virtual const gchar* str_value() = 0;
    
        // Endpoints
        virtual st_ep* ep_this() = 0;
        virtual GList* ep_list() = 0;

        // Nodes
        GNode* node() { g_assert(m_active); return m_node; }

    protected:
        // Active
        bool m_active;
        
        // Node
        GNode* m_node;
};

// Hardware layer class
class c_layer_hw : public c_layer {
    public:
        // Constructor and destructor
        c_layer_hw();
        ~c_layer_hw();
        
        // Init and end
        bool init_unpack(st_pck_drv* pck);
        void end();
        
        // Types
        en_layer_type type() { return LAYER_HW_PCK; }
        
        // Output
        void str_dump();
        const gchar* str_name();
        const gchar* str_value();
    
        // Endpoints
        st_ep* ep_this() { g_assert(m_active); return NULL; }
        GList* ep_list() { g_assert(m_active); return NULL; }

    private:
        // Driver
        c_drv* m_drv;
};

#endif

