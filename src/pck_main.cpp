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

// Int inc
#include "ao_config.h"
#include "ao_util.h"
#include "pck_main.h"
#include "pck_ieee80211.h"
//#include "pck_ieee8023.h"
#include "pck_radiotap.h"

// Constructor and destructor
c_layer_hw::c_layer_hw()
{
    // Deactive
    m_active = false;
}

c_layer_hw::~c_layer_hw()
{
    // End
    if (m_active)
        end();
}

// Init and end
bool c_layer_hw::init_unpack(st_pck_drv* pck)
{
    // Check
    g_assert(!m_active);

    // Node
    m_node = g_node_new(this);
    
    // Driver
    m_drv = pck->driver;
    
    // Debug
    //c_util::hex_log("[pck] layer-hw hexdump!", pck->data->data, pck->data->len);
    
    // Layer
    switch (pck->type) {
        case LAYER_80211_PCK:
            {
                //g_message("[pck] layer-hw: next=layer-80211");
                c_layer_80211* layer = new c_layer_80211();
                if (!layer->init_unpack(m_node, pck->data))
                    delete layer;
            }
            break;
        case LAYER_RADIOTAP_PCK:
            {
                //g_message("[pck] layer-hw: next=layer-radiotap");
                c_layer_radiotap* layer = new c_layer_radiotap();
                if (!layer->init_unpack(m_node, pck->data))
                    delete layer;
            }
            break;
        /*
        case LAYER_8023_PCK:
            {
                //g_message("[pck] layer-hw: next=layer-8023");
                c_layer_8023* layer = new c_layer_8023();
                if (!layer->init_unpack(m_node, pck->data))
                    delete layer;
            }
            break;
        */
    }
    
    // Packet delete
    g_byte_array_unref(pck->data);
    g_free(pck);
    
    // Activate
    m_active = true;
    return true;
}

void c_layer_hw::end()
{
    // Check
    g_assert(m_active);
    
    // Layers
    g_node_unlink(m_node);
    while (g_node_first_child(m_node)) {
        GNode* node = g_node_first_child(m_node);
        c_layer* layer = (c_layer*) node->data;
        delete layer;
    }
    g_node_destroy(m_node);
    
    // Deactive
    m_active = false;
}

// Output
void c_layer_hw::str_dump()
{
    // Check
    g_assert(m_active);
}

const gchar* c_layer_hw::str_name()
{
    // Check
    g_assert(m_active);
    
    // String
    return "HW";
}

const gchar* c_layer_hw::str_value()
{
    // Check
    g_assert(m_active);
    
    // String
    return m_drv->name();
}

////////////////////////////////////////////////////////////////////////////////
/*
void ao_pck_log(st_ao_packet* pck)
{
    
    // Layer 4
    if ((pck->m4_type == AO_M4_TCP) && (dshow & AO_PROTO_L4_TCP)) {

        g_print("* tcp! port_src=%hu, port_dst=%hu, checksum=0x%04x, len=%hu\n",
            ntohs(pck->m4.tcp.hdr->th_sport), ntohs(pck->m4.tcp.hdr->th_dport),
            ntohs(pck->m4.tcp.hdr->th_sum), pck->m4.tcp.hdr->th_off * 4
        );
        g_print("* tcp! res_seq=0x%08x, ack_seq=0x%08x, fin=%u, syn=%u, rst=%u, psh=%u, ack=%u, urg=%u\n", //, ece=%u, cwr=%u
            ntohl(pck->m4.tcp.hdr->th_seq), ntohl(pck->m4.tcp.hdr->th_ack),
            pck->m4.tcp.hdr->th_flags & TH_FIN, pck->m4.tcp.hdr->th_flags & TH_SYN, 
			pck->m4.tcp.hdr->th_flags & TH_RST, pck->m4.tcp.hdr->th_flags & TH_PUSH,
			pck->m4.tcp.hdr->th_flags & TH_ACK, pck->m4.tcp.hdr->th_flags & TH_URG
            //pck->m4.tcp.hdr->ece, pck->m4.tcp.hdr->cwr
        );
        if (pck->m4.tcp.ts) {
            g_print("* tcp! time_a=0x%08x, time_b=0x%08x\n", ntohl(pck->m4.tcp.ts->time_a), ntohl(pck->m4.tcp.ts->time_b));
        }
        //dumphex_c(pck->m2_data, pck->m2_size);

    } else if ((pck->m4_type == AO_M4_UDP) && (dshow & AO_PROTO_L4_UDP)) {

        g_print("* udp! port_src=%hu, port_dst=%hu, checksum=0x%04x, len=%hu\n",
            ntohs(pck->m4.udp.hdr->uh_sport), ntohs(pck->m4.udp.hdr->uh_dport),
            ntohs(pck->m4.udp.hdr->uh_sum), ntohs(pck->m4.udp.hdr->uh_ulen)
        );

    }
}
*/

