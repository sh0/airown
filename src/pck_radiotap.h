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
        static const guint m_ext_num = 5;
        guint32 m_ext_val[m_ext_num];
        
        // Flags
        bool m_flags_set;
        guint8 m_flags_val;
        
        // Rate
        bool m_rate_set;
        guint8 m_rate_val;
        
        // Channel
        bool m_chan_set;
        struct {
            guint16 freq;
            guint16 flags;
        } __attribute__((__packed__)) m_chan_val;
        
        // FHSS
        bool m_fhss_set;
        struct {
            guint8 hop_set;
            guint8 hop_pattern;
        } __attribute__((__packed__)) m_fhss_val;
        
        // Antenna noise
        bool m_ant_noise_set;
        gint8 m_ant_noise_val;
        
        // Antenna signal dB
        bool m_ant_signal_db_set;
        guint8 m_ant_signal_db_val;
        
        // TX flags
        bool m_txflags_set;
        guint16 m_txflags_val;
        
        // Endpoints
        st_ep m_ep;
};

#endif

