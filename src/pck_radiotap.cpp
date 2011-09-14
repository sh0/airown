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
	
	// Extended presence
	m_ext_val[0] = m_hdr.it_present;
	for (guint i=1; i<m_ext_num; i++) {
	    if (m_ext_val[i - 1] & (1 << 31)) {
	        if (optlen < (gint)sizeof(guint32))
	            return false;
	        m_ext_val[i] = *((guint32*)data_cur);
	        data_cur += sizeof(guint32);
	        optlen -= sizeof(guint32);
	    } else {
	        m_ext_val[i] = 0;
	        break;
	    }
	}
	
	// Options
	m_flags_set = false;
	m_rate_set = false;
	m_chan_set = false;
	m_fhss_set = false;
	m_ant_noise_set = false;
	m_ant_signal_db_set = false;
	m_txflags_set = false;
	for (guint i=0; i<m_ext_num; i++) {
	    // Scan bits
	    for (guint b=0; b<31; b++) {
	        // Check
	        if (!(m_ext_val[i] & (1 << b)))
	            continue;
	        
	        // Select field
	        guint id = (i * 30) + b + 1;
	        switch (id) {
	            case 1:
	                // Flags
	                if (optlen < (gint)sizeof(m_flags_val))
	                    goto opt_continue;
	                m_flags_set = true;
	                m_flags_val = *data_cur;
	                data_cur += sizeof(m_flags_val);
	                optlen -= sizeof(m_flags_val);
	                break;
	                
	            case 2:
                    // Rate
	                if (optlen < (gint)sizeof(m_rate_val))
	                    goto opt_continue;
	                m_rate_set = true;
	                m_rate_val = *data_cur;
	                data_cur += sizeof(m_rate_val);
	                optlen -= sizeof(m_rate_val);
	                break;
	                
	            case 3:
	                // Channel
	                if (optlen < (gint)sizeof(m_chan_val))
	                    goto opt_continue;
	                m_chan_set = true;
	                g_memmove(&m_chan_val, data_cur, sizeof(m_chan_val));
	                data_cur += sizeof(m_chan_val);
	                optlen -= sizeof(m_chan_val);
	                break;
	            
	            case 4:
	                // FHSS
	                if (optlen < (gint)sizeof(m_fhss_val))
	                    goto opt_continue;
	                m_fhss_set = true;
	                g_memmove(&m_fhss_val, data_cur, sizeof(m_fhss_val));
	                data_cur += sizeof(m_fhss_val);
	                optlen -= sizeof(m_fhss_val);
	                break;
	            
	            case 6:
	                // Antenna noise
	                if (optlen < (gint)sizeof(m_ant_noise_val))
	                    goto opt_continue;
	                m_ant_noise_set = true;
	                m_ant_noise_val = (gint8) *data_cur;
	                data_cur += sizeof(m_ant_noise_val);
	                optlen -= sizeof(m_ant_noise_val);
	                break;
	            
	            case 12:
	                // Antenna noise
	                if (optlen < (gint)sizeof(m_ant_signal_db_val))
	                    goto opt_continue;
	                m_ant_signal_db_set = true;
	                m_ant_signal_db_val = *data_cur;
	                data_cur += sizeof(m_ant_signal_db_val);
	                optlen -= sizeof(m_ant_signal_db_val);
	                break;
	            
	            case 15:
	                // TX flags
	                if (optlen < (gint)sizeof(m_txflags_val))
	                    goto opt_continue;
	                m_txflags_set = true;
	                g_memmove(&m_txflags_val, data_cur, sizeof(m_txflags_val));
	                data_cur += sizeof(m_txflags_val);
	                optlen -= sizeof(m_txflags_val);
	                break;
	            
	            default:
	                // Unknown op
	                g_message("[pck] unhandled=%u, optlen=%d", id, optlen);
	                goto opt_continue;
	        }
	    }
	
	    // End of flag variables
	    if (!(m_ext_val[i] & (1 << 31)))
	        break;
	}
	opt_continue:
	
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

    // Message
	g_message(
	    "[pck] layer-radiotap: version=%u, len=%u, flags=%08x",
	    m_hdr.it_version, m_hdr.it_len, m_hdr.it_present
	);
	if (m_rate_set)
	    g_message("[pck] * rate=[%.2f Mbps]", (gdouble)m_rate_val * 0.5);
	if (m_chan_set)
	    g_message(
	        "[pck] * freq=[%.3f GHz], turbo=%s, cck=%s, ofdm=%s, 2ghz=%s, 5ghz=%s, passive=%s",
	        (gdouble)m_chan_val.freq / 1000.0,
	        m_chan_val.flags & 0x0010 ? "true" : "false",
	        m_chan_val.flags & 0x0020 ? "true" : "false",
	        m_chan_val.flags & 0x0040 ? "true" : "false",
	        m_chan_val.flags & 0x0080 ? "true" : "false",
	        m_chan_val.flags & 0x0100 ? "true" : "false",
	        m_chan_val.flags & 0x0200 ? "true" : "false"
	    );
    if (m_fhss_set)
        g_message("[pck] * hop_set=%u, hop_pattern=%u", m_fhss_val.hop_set, m_fhss_val.hop_pattern);
    if (m_ant_noise_set)
        g_message("[pck] * ant_noise=[%d dBm]", m_ant_noise_val);
    if (m_ant_signal_db_set)
        g_message("[pck] * ant_signal=[%u dB]", m_ant_signal_db_val);
    if (m_txflags_set) {
        g_message(
            "[pck] * retry_fail=%s, cts_to_self=%s, rts_cts_used=%s, no_ack_expected=%s, has_seqno=%s",
            m_txflags_val & 0x0001 ? "true" : "false",
            m_txflags_val & 0x0002 ? "true" : "false",
            m_txflags_val & 0x0004 ? "true" : "false",
            m_txflags_val & 0x0008 ? "true" : "false",
            m_txflags_val & 0x0010 ? "true" : "false"
        );
    }
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

