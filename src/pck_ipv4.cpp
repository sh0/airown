/*
 * Airown - IPv4 packets
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
#include "pck_ipv4.h"
#include "pck_tcp.h"
#include "pck_udp.h"

// <===> IPv4 endpoint <=======================================================>

// Constructor and destructor
c_ep_ipv4::c_ep_ipv4(struct in_addr* addr)
{
    m_str = NULL;
    c_util::cpy_ipv4(&m_addr, addr);
    if (m_addr.s_addr == 0xffffffff)
        m_cast = EP_CAST_BROADCAST;
    else if ((m_addr.s_addr & 0xf0) == 224)
        m_cast = EP_CAST_MULTICAST;
    else if ((m_addr.s_addr & 0xff) == 127)
        m_cast = EP_CAST_LOOPBACK;
    else
        m_cast = EP_CAST_UNICAST;
}

c_ep_ipv4::c_ep_ipv4(c_ep_ipv4* ep_b)
{
    m_str = NULL;
    c_ep_ipv4* ep_c = dynamic_cast<c_ep_ipv4*>(ep_b);
    c_util::cpy_ipv4(&m_addr, &(ep_c->m_addr));
    m_cast = ep_c->m_cast;
}

c_ep_ipv4::~c_ep_ipv4()
{
    if (m_str)
        g_free(m_str);
}

// Types
guint c_ep_ipv4::cast()
{
    return m_cast;
}

// Compare
bool c_ep_ipv4::cmp(c_ep* ep_b)
{
    c_ep_ipv4* ep_c = dynamic_cast<c_ep_ipv4*>(ep_b);
    return c_util::cmp_ipv4(&m_addr, &(ep_c->m_addr));
}

// Output
void c_ep_ipv4::str_dump()
{
    g_message(
        "[pck] ep-ipv4 -> addr=[%u.%u.%u.%u]",
        (m_addr.s_addr) & 0xff, (m_addr.s_addr >> 8) & 0xff, (m_addr.s_addr >> 16) & 0xff, (m_addr.s_addr >> 24) & 0xff
    );
}

const gchar* c_ep_ipv4::str_name()
{
    return "IPv4";
}

const gchar* c_ep_ipv4::str_value()
{
    if (!m_str)
        m_str = g_strdup_printf(
            "%u.%u.%u.%u",
            (m_addr.s_addr) & 0xff, (m_addr.s_addr >> 8) & 0xff, (m_addr.s_addr >> 16) & 0xff, (m_addr.s_addr >> 24) & 0xff
        );
    return m_str;
}
    
// <===> IPv4 layer <==========================================================>

// Constructor and destructor
c_layer_ipv4::c_layer_ipv4()
{
    // Deactive
    m_active = false;
}

c_layer_ipv4::~c_layer_ipv4()
{
    // End
    if (m_active)
        end();
}

// Init and end
bool c_layer_ipv4::init_unpack(GNode* node, GByteArray* data)
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
    if (m_hdr.ip_v != 4)
        return false;
    
    // Header size check
    guint hdrlen = 4 * m_hdr.ip_hl;
    if (hdrlen < sizeof(m_hdr))
        return false;
    
    // Size check
    if (data->len < g_ntohs(m_hdr.ip_len))
        return false;
    data_end = data->data + g_ntohs(m_hdr.ip_len);
    
    // Checksum check
    guint32 chk_val = 0;
    for (guint i=0; i<MIN(hdrlen, data->len + 1)/2; i++)
        chk_val += ((guint16*) data->data)[i];
    chk_val = (chk_val >> 16) + (chk_val & 0xffff);
    if (chk_val != 0xffff)
        return false;
    
    // Next layer check
    if (m_hdr.ip_p != IPPROTO_TCP && m_hdr.ip_p != IPPROTO_UDP)
        return false;
    
    // Options
    guint optlen = hdrlen - sizeof(m_hdr);
    if (data_end - data_cur < optlen)
        return false;
    for (guint i=0; i<optlen; ) {
        guint8 o_flags = data_cur[i++] & 0x7f;
        if (o_flags == IPOPT_EOL) {
            // End Of Options List
            break;
        } else if (o_flags == IPOPT_NOP) {
            // No Operation
            continue;
        } else if (o_flags == IPOPT_RR) {
            // Record Route
            break;
        } else if (o_flags == IPOPT_TS) {
            // Timestamp
            break;
        } else if (o_flags == IPOPT_SECURITY) {
            // Security
            break;
        } else if (o_flags == IPOPT_LSRR) {
            // Loose Source Record Route
            break;
        } else if (o_flags == IPOPT_SATID) {
            // Satnet Id
            break;
        } else if (o_flags == IPOPT_SSRR) {
            // Strict Source Record Route
            break;
        } else {
            // Unknown operation
            break;
        }
    }
    data_cur += optlen;
    
    // Endpoints
    m_ep.src = new c_ep_ipv4(&m_hdr.ip_src);
    m_ep.dst = new c_ep_ipv4(&m_hdr.ip_dst);
    m_ep.net = NULL;
    
    // Free data
    if (data_end < data->data + data->len)
        g_byte_array_remove_range(data, data_end - data->data, data->data + data->len - data_end);
    g_byte_array_remove_range(data, 0, data_cur - data->data);
    
    // Node
    m_node = g_node_new(this);
    g_assert(node);
    g_node_append(m_node, node);
    
    // Debug
    /*
    g_message("[pck] <========================================================================>");
    str_dump();
    c_util::hex_log("[pck] layer-ipv4 hexdump!", data->data, data->len);
    */
    
    // Next layer
    if ((g_ntohs(m_hdr.ip_off) & IP_OFFMASK) == 0 && (g_ntohs(m_hdr.ip_off) & IP_MF) == 0) {
        // Not fragmented
        switch (m_hdr.ip_p) {
            case IPPROTO_TCP:
                {
                    //g_message("[pck] layer-ipv4: next=layer-tcp");
                    c_layer_tcp* next = new c_layer_tcp();
                    if (!next->init_unpack(m_node, data))
                        delete next;
                }
                break;
            case IPPROTO_UDP:
                {
                    //g_message("[pck] layer-ipv4: next=layer-udp");
                    c_layer_udp* next = new c_layer_udp();
                    if (!next->init_unpack(m_node, data))
                        delete next;
                }
                break;
        }
    } else {
        // Fragmented
        g_warning("[pck] TODO: fragmented ipv4 packet!");
    }
    
    // Return
    m_active = true;
    return true;
}

void c_layer_ipv4::end()
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
void c_layer_ipv4::str_dump()
{
    // Check
    g_assert(m_active);
    
    // Message
    g_message("[pck] layer-ipv4: proto=%s, src=%s, dst=%s, ip_len=%u",
        m_hdr.ip_p == IPPROTO_TCP ? "tcp" :
        (m_hdr.ip_p == IPPROTO_UDP ? "udp" :
        (m_hdr.ip_p == IPPROTO_ICMP ? "icmp" : "unknown")),
        m_ep.src->str_value(), m_ep.dst->str_value(),
        g_ntohs(m_hdr.ip_len)
    );
}

const gchar* c_layer_ipv4::str_name()
{
    // Check
    g_assert(m_active);
    
    // String
    return "IPv4";
}

const gchar* c_layer_ipv4::str_value()
{
    // Check
    g_assert(m_active);
    
    // String
    return "Data frame";
}

