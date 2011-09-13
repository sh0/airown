/*
 * Airown - Radiotap packets
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

#ifndef H_PCK_RADIOTAP
#define H_PCK_RADIOTAP

// Int inc
#include "ao_config.h"
#include "pck_main.h"

// Radiotap header
struct radiotap_header {
    guint8 it_version; /* set to 0 */
    guint8 it_pad;
    guint16 it_len; /* entire length */
    guint32 it_present; /* fields present */
} __attribute__((__packed__));

class c_layer_radiotap : public c_layer {
    public:
        // Constructor and destructor
        c_layer_radiotap();
        ~c_layer_radiotap();
        
        // Init and end
        bool init_unpack(GNode* node, GByteArray* data);
        void end();
        
        // Types
        en_layer_type type() { return LAYER_RADIOTAP_PCK; }
        
        // Output
        void str_dump();
        const gchar* str_name();
        const gchar* str_value();
    
        // Endpoints
        st_ep* ep_this() { g_assert(m_active); return &m_ep; }
        GList* ep_list() { g_assert(m_active); return NULL; }
        
    private:
        // Headers
        struct radiotap_header m_hdr;
        
        // Endpoints
        st_ep m_ep;
};

#endif

