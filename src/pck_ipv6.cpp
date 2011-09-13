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

// Int inc
#include "ao_config.h"
#include "ao_util.h"
#include "pck_ipv6.h"
#include "pck_tcp.h"
#include "pck_udp.h"

// <===> IPv6 endpoint <=======================================================>

// Constructor and destructor
c_ep_ipv6::c_ep_ipv6(struct libnet_in6_addr* addr)
{
    m_str = NULL;
    c_util::cpy_ipv6(&m_addr, addr);
    m_cast = EP_CAST_UNICAST;
}

c_ep_ipv6::c_ep_ipv6(c_ep_ipv6* ep_b)
{
    m_str = NULL;
    c_ep_ipv6* ep_c = dynamic_cast<c_ep_ipv6*>(ep_b);
    c_util::cpy_ipv6(&m_addr, &(ep_c->m_addr));
    m_cast = ep_c->m_cast;
}

c_ep_ipv6::~c_ep_ipv6()
{
    if (m_str)
        g_free(m_str);
}

// Types
guint c_ep_ipv6::cast()
{
    return m_cast;
}

// Compare
bool c_ep_ipv6::cmp(c_ep* ep_b)
{
    c_ep_ipv6* ep_c = dynamic_cast<c_ep_ipv6*>(ep_b);
    return c_util::cmp_ipv6(&m_addr, &(ep_c->m_addr));
}

// Output
void c_ep_ipv6::str_dump()
{
    guint16* saddr = m_addr.__u6_addr.__u6_addr16;
    g_message(
        "[pck] ep-ipv6 -> addr=[%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x]",
        saddr[0], saddr[1], saddr[2], saddr[3], saddr[4], saddr[5], saddr[6], saddr[7]
    );
}

const gchar* c_ep_ipv6::str_name()
{
    return "IPv6";
}

const gchar* c_ep_ipv6::str_value()
{
    if (!m_str) {
        guint16* saddr = m_addr.__u6_addr.__u6_addr16;
        m_str = g_strdup_printf(
            "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x",
            saddr[0], saddr[1], saddr[2], saddr[3], saddr[4], saddr[5], saddr[6], saddr[7]
        );
    }
    return m_str;
}

// <===> IPv6 layer <==========================================================>

// Constructor and destructor
c_layer_ipv6::c_layer_ipv6()
{
    // Deactive
    m_active = false;
}

c_layer_ipv6::~c_layer_ipv6()
{
    // End
    if (m_active)
        end();
}

// Init and end
bool c_layer_ipv6::init_unpack(GNode* node, GByteArray* data)
{
    // Check
    g_assert(!m_active);
    
	// Data pointers
	guint8* data_cur = data->data;
	guint8* data_end = data_cur + data->len;

    // Header
	if ((guint)(data_end - data_cur) < sizeof(m_hdr))
	    return false;
    g_memmove(&m_hdr, data_cur, sizeof(m_hdr));
    data_cur += sizeof(m_hdr);
    
    // Version check
    if ((m_hdr.ip_flags[0] >> 4) != 6)
        return false;
    
    // Payload size check
    if (data_end - data_cur < m_hdr.ip_len)
        return false;
    
    // Next layer check
    if (m_hdr.ip_nh != IPPROTO_TCP && m_hdr.ip_nh != IPPROTO_UDP)
        return false;
    
    // Endpoints
    m_ep.src = new c_ep_ipv6(&m_hdr.ip_src);
    m_ep.dst = new c_ep_ipv6(&m_hdr.ip_dst);
    m_ep.net = NULL;
    
    // Free data
    g_byte_array_remove_range(data, 0, data_cur - data->data);
    
    // Node
    m_node = g_node_new(this);
    g_assert(node);
    g_node_append(m_node, node);
    
    // Next layer
    switch (m_hdr.ip_nh) {
        case IPPROTO_TCP:
            {
                c_layer_tcp* next = new c_layer_tcp();
                if (!next->init_unpack(m_node, data))
                    delete next;
            }
            break;
        case IPPROTO_UDP:
            {
                c_layer_udp* next = new c_layer_udp();
                if (!next->init_unpack(m_node, data))
                    delete next;
            }
            break;
    }
    
    // Return
    m_active = true;
    return true;
}

void c_layer_ipv6::end()
{
    // Check
    g_assert(m_active);
    
    // Endpoints
    if (m_ep.src)
        delete m_ep.src;
    if (m_ep.dst)
        delete m_ep.dst;
    
    // Deactivate
    m_active = false;
}

// Output
void c_layer_ipv6::str_dump()
{
    // Check
    g_assert(m_active);
    
    // Message
    g_message("[pck] layer-ipv6: proto=%s, src=%s, dst=%s",
        m_hdr.ip_nh == IPPROTO_TCP ? "tcp" :
        (m_hdr.ip_nh == IPPROTO_UDP ? "udp" :
        (m_hdr.ip_nh == IPPROTO_ICMP6 ? "icmp6" : "unknown")),
        m_ep.src->str_value(), m_ep.dst->str_value()
    );
}

const gchar* c_layer_ipv6::str_name()
{
    // Check
    g_assert(m_active);
    
    // String
    return "IPv6";
}

const gchar* c_layer_ipv6::str_value()
{
    // Check
    g_assert(m_active);
    
    // String
    return "Data frame";
}

/*
// Functions
void pck_ipv6_read(st_ao_packet* pck)
{
    // IPv6 header
    pck->m3.ipv6.hdr = NULL;
    if (pck->m3_size >= sizeof(struct libnet_ipv6_hdr)) {
    
        // Set type
        pck->m3_type = AO_M3_IPV6;
        
        // Header
        pck->m3.ipv6.hdr = (struct libnet_ipv6_hdr*)(pck->m3_data);
        
        // Data
        pck->m4_data = pck->m3_data + sizeof(struct libnet_ipv6_hdr);
        pck->m4_size = pck->m3_size - sizeof(struct libnet_ipv6_hdr);
        
        // Next layer
        switch (pck->m3.ipv6.hdr->ip_nh) {
            case IPPROTO_TCP:
                pck_tcp_read(pck);
                break;
            case IPPROTO_UDP:
                pck_udp_read(pck);
                break;
        }
    }
}
*/

