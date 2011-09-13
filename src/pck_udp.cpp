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

// Int inc
#include "ao_config.h"
#include "pck_udp.h"

// <===> UDP endpoint <========================================================>

// Constructor and destructor
c_ep_udp::c_ep_udp(guint16 port)
{
    m_str = NULL;
    m_port = port;
}

c_ep_udp::c_ep_udp(c_ep_udp* ep_b)
{
    m_str = NULL;
    c_ep_udp* ep_c = dynamic_cast<c_ep_udp*>(ep_b);
    m_port = ep_c->m_port;
}

c_ep_udp::~c_ep_udp()
{
    if (m_str)
        g_free(m_str);
}

// Types
guint c_ep_udp::cast()
{
    return EP_CAST_NONE;
}

// Compare
bool c_ep_udp::cmp(c_ep* ep_b)
{
    c_ep_udp* ep_c = dynamic_cast<c_ep_udp*>(ep_b);
    return (m_port == ep_c->m_port ? true : false);
}

// Output
void c_ep_udp::str_dump()
{
    g_message("[pck] ep-udp -> port=%u", m_port);
}

const gchar* c_ep_udp::str_name()
{
    return "UDP";
}

const gchar* c_ep_udp::str_value()
{
    if (!m_str)
        m_str = g_strdup_printf("%u", m_port);
    return m_str;
}

// <===> UDP layer <===========================================================>

// Constructor and destructor
c_layer_udp::c_layer_udp()
{
    // Deactive
    m_active = false;
}

c_layer_udp::~c_layer_udp()
{
    // End
    if (m_active)
        end();
}

// Init and end
bool c_layer_udp::init_unpack(GNode* node, GByteArray* data)
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

    // Payload size check
    guint16 datalen = g_ntohs(m_hdr.uh_ulen);
    if ((guint)(data_end - data_cur) < datalen)
	    return false;

    // Endpoints
    m_ep.src = new c_ep_udp(m_hdr.uh_sport);
    m_ep.dst = new c_ep_udp(m_hdr.uh_dport);
    m_ep.net = NULL;
    
    // Free data
    g_byte_array_remove_range(data, 0, data_cur - data->data);
    
    // Node
    m_node = g_node_new(this);
    g_assert(node);
    g_node_append(m_node, node);

    // Assembler layer

    // Return
    m_active = true;
    return true;
}

void c_layer_udp::end()
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
void c_layer_udp::str_dump()
{
    // Check
    g_assert(m_active);
    
    // Message
    g_message("[pck] layer-udp: src=%s, dst=%s", m_ep.src->str_value(), m_ep.dst->str_value());
}

const gchar* c_layer_udp::str_name()
{
    // Check
    g_assert(m_active);
    
    // String
    return "UDP";
}

const gchar* c_layer_udp::str_value()
{
    // Check
    g_assert(m_active);
    
    // String
    return "Data frame";
}

