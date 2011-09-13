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

// Int inc
#include "ao_config.h"
#include "pck_radiotap.h"
#include "pck_ieee80211.h"

// Constructor and destructor
c_layer_radiotap::c_layer_radiotap()
{
    // Deactive
    m_active = false;
}

c_layer_radiotap::~c_layer_radiotap()
{
    // End
    if (m_active)
        end();
}

// Init and end
bool c_layer_radiotap::init_unpack(GNode* node, GByteArray* data)
{
    // Check
    g_assert(!m_active);
    
	// Data pointers
	guint8* data_cur = data->data;
	guint8* data_end = data_cur + data->len;

    // Radiotap header
	if ((guint)(data_end - data_cur) < sizeof(m_hdr))
	    return false;
    g_memmove(&m_hdr, data_cur, sizeof(m_hdr));
    data_cur += sizeof(m_hdr);
    
    // Check size
    gint optlen = (gint)m_hdr.it_len - (gint)sizeof(m_hdr);
	if (data_end - data_cur < optlen)
	    return false;
	
	// Check version
	if (m_hdr.it_version != 0)
	    return false;
	
	// Skip options
	data_cur += optlen;
	
	// Endpoints
	m_ep.src = NULL;
	m_ep.dst = NULL;
	m_ep.net = NULL;
	
    // Free data
    g_byte_array_remove_range(data, 0, data_cur - data->data);

    // Node
    m_node = g_node_new(this);
    g_assert(node);
    g_node_append(m_node, node);
    
    // Next layer
    c_layer_80211* next = new c_layer_80211();
    if (!next->init_unpack(m_node, data))
        delete next;

    // Activate
    m_active = true;
    return true;
}

void c_layer_radiotap::end()
{
    // Check
    g_assert(m_active);
    
    // Deactive
    m_active = false;
}

// Output
void c_layer_radiotap::str_dump()
{
    // Check
    g_assert(m_active);
}

const gchar* c_layer_radiotap::str_name()
{
    // Check
    g_assert(m_active);
    
    // String
    return "Radiotap";
}

const gchar* c_layer_radiotap::str_value()
{
    // Check
    g_assert(m_active);
    
    // String
    return "Data frame";
}

