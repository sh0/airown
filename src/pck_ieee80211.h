/*
 * Airown - IEEE 802.11 packets
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

#ifndef H_PCK_IEEE80211
#define H_PCK_IEEE80211

// Int inc
#include "ao_config.h"
#include "pck_main.h"
#include "pck_ieee80211_defs.h"
#include "pck_ieee80211_common.h"

// <===> IEEE 802.11 endpoint <================================================>

class c_ep_80211 : public c_ep {
    public:
        // Constructor and destructor
        c_ep_80211(guint8* addr);
        c_ep_80211(c_ep_80211* ep);
        ~c_ep_80211();
        
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
        guint8 m_addr[6];
        gchar* m_str;
};

// <===> IEEE 802.11 layer <===================================================>

class c_layer_80211 : public c_layer {
    public:
        // Constructor and destructor
        c_layer_80211();
        ~c_layer_80211();
        
        // Init and end
        bool init_unpack(GNode* node, GByteArray* data);
        void end();
        
        // Types
        en_layer_type type() { return LAYER_80211_PCK; }
        
        // Output
        void str_dump();
        const gchar* str_name();
        const gchar* str_value();
    
        // Endpoints
        st_ep* ep_this() { g_assert(m_active); return &m_ep; }
        GList* ep_list() { g_assert(m_active); return NULL; }
        
    private:
        // Headers
        union {
            struct {
                // Frame control and duration id only
                struct ieee80211_fc m_fc;
            };
            struct {
                // Management header
                struct ieee80211_mgmt m_mgmt;
            };
            struct {
                // Control headers
                union {
                    struct ieee80211_ctrl_rts m_ctrl_rts;
                    struct ieee80211_ctrl_cts m_ctrl_cts;
                    struct ieee80211_ctrl_ack m_ctrl_ack;
                    struct ieee80211_ctrl_pspoll m_ctrl_pspoll;
                    struct ieee80211_ctrl_cfend m_ctrl_cfend;
                };
            };
            struct {
                // Data headers
                struct ieee80211_hdr m_hdr;
                guint8 m_addr4[6];
                struct ieee80211_qos m_qos;
                struct libnet_802_2snap_hdr m_snap;
            };
        };
        
        // Endpoints
        st_ep m_ep;
};

#endif

