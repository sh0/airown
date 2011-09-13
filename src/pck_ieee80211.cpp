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

// Int inc
#include "ao_config.h"
#include "ao_util.h"
#include "pck_ieee80211.h"
#include "pck_ipv4.h"
#include "pck_ipv6.h"

// Defines
static const guint16 LLC_TYPE_IPV4 = 0x0008;
static const guint16 LLC_TYPE_IPV6 = 0xDD86;
static const guint16 LLC_TYPE_ARP = 0x0608;

// <===> IEEE 802.11 endpoint <================================================>

// Constructor and destructor
c_ep_80211::c_ep_80211(guint8* addr)
{
    m_str = NULL;
    g_memmove(m_addr, addr, sizeof(m_addr));
    m_cast = EP_CAST_UNICAST;
    for (guint i=0; i<sizeof(m_addr); i++)
        if (m_addr[i] != 0xff)
            return;
    m_cast = EP_CAST_BROADCAST;
}

c_ep_80211::c_ep_80211(c_ep_80211* ep)
{
    m_str = NULL;
    g_memmove(m_addr, ep->m_addr, sizeof(m_addr));
    m_cast = EP_CAST_UNICAST;
    for (guint i=0; i<sizeof(m_addr); i++)
        if (m_addr[i] != 0xff)
            return;
    m_cast = EP_CAST_BROADCAST;
}

c_ep_80211::~c_ep_80211()
{
    if (!m_str)
        g_free(m_str);
}

// Functions
guint c_ep_80211::cast()
{
    return m_cast;
}

bool c_ep_80211::cmp(c_ep* ep_b)
{
    c_ep_80211* ep_c = dynamic_cast<c_ep_80211*>(ep_b);
    for (guint i=0; i<sizeof(m_addr); i++)
        if (m_addr[i] != ep_c->m_addr[i])
            return false;
    return true;
}

void c_ep_80211::str_dump()
{
    g_message(
        "[pck] ep-80211 -> addr=[%02x%02x%02x%02x%02x%02x] cast=%s",
        m_addr[0], m_addr[1], m_addr[2], m_addr[3], m_addr[4], m_addr[5],
        m_cast == EP_CAST_UNICAST ? "unicast" : (m_cast == EP_CAST_BROADCAST ? "broadcast" : "multicast")
    );
}

const gchar* c_ep_80211::str_name()
{
    return "802.11";
}

const gchar* c_ep_80211::str_value()
{
    if (!m_str)
        m_str = g_strdup_printf("%02x%02x%02x%02x%02x%02x", m_addr[0], m_addr[1], m_addr[2], m_addr[3], m_addr[4], m_addr[5]);
    return m_str;
}

// <===> IEEE 802.11 layer <===================================================>

// Constructor and destructor
c_layer_80211::c_layer_80211()
{
    // Deactive
    m_active = false;
}

c_layer_80211::~c_layer_80211()
{
    // End
    if (m_active)
        end();
}

// Init and end
bool c_layer_80211::init_unpack(GNode* node, GByteArray* data)
{
    // Check
    g_assert(!m_active);
    
    // Debug
    //c_util::hex_log("[pck] layer-80211 hexdump!", data->data, data->len);
    
    // Next layer
    bool next_layer = false;
    
	// Data pointers
	guint8* data_cur = data->data;
	guint8* data_end = data_cur + data->len;

    // IEEE 802.11 header
	if ((guint)(data_end - data_cur) < sizeof(m_fc))
	    return false;
    g_memmove(&m_fc, data_cur, sizeof(m_fc));
    
    // Data packets
    guint mtype = WLAN_FC_GET_TYPE(m_fc.frame_control);
    guint stype = WLAN_FC_GET_STYPE(m_fc.frame_control);
    if (mtype == WLAN_FC_TYPE_MGMT) {
    
        // Management header
	    if ((guint)(data_end - data_cur) < sizeof(m_mgmt) - sizeof(m_mgmt.u))
	        return false;
        g_memmove(&m_mgmt, data_cur, sizeof(m_mgmt) - sizeof(m_mgmt.u));
        data_cur += sizeof(m_mgmt) - sizeof(m_mgmt.u);
        
        // Select subtype
        switch(stype) {
            case WLAN_FC_STYPE_ASSOC_REQ:
                // ASSOCREQ
                if ((guint)(data_end - data_cur) < sizeof(m_mgmt.u.assoc_req))
                    return false;
                g_memmove(&m_mgmt.u.assoc_req, data_cur, sizeof(m_mgmt.u.assoc_req));
                data_cur += sizeof(m_mgmt.u.assoc_req);
                
                break;
            case WLAN_FC_STYPE_ASSOC_RESP:
                // ASSOCRESP
                if ((guint)(data_end - data_cur) < sizeof(m_mgmt.u.assoc_resp))
                    return false;
                g_memmove(&m_mgmt.u.assoc_resp, data_cur, sizeof(m_mgmt.u.assoc_resp));
                data_cur += sizeof(m_mgmt.u.assoc_resp);
                
                break;
            case WLAN_FC_STYPE_REASSOC_REQ:
                // REASSOCREQ
                if ((guint)(data_end - data_cur) < sizeof(m_mgmt.u.reassoc_req))
                    return false;
                g_memmove(&m_mgmt.u.assoc_req, data_cur, sizeof(m_mgmt.u.assoc_req));
                data_cur += sizeof(m_mgmt.u.reassoc_req);
                
                break;
            case WLAN_FC_STYPE_REASSOC_RESP:
                // REASSOCRESP
                if ((guint)(data_end - data_cur) < sizeof(m_mgmt.u.reassoc_resp))
                    return false;
                g_memmove(&m_mgmt.u.reassoc_resp, data_cur, sizeof(m_mgmt.u.reassoc_resp));
                data_cur += sizeof(m_mgmt.u.reassoc_resp);
                
                break;
            case WLAN_FC_STYPE_PROBE_REQ:
                // PROBEREQ
                if ((guint)(data_end - data_cur) < sizeof(m_mgmt.u.probe_req))
                    return false;
                g_memmove(&m_mgmt.u.probe_req, data_cur, sizeof(m_mgmt.u.probe_req));
                data_cur += sizeof(m_mgmt.u.probe_req);
                
                break;
            case WLAN_FC_STYPE_PROBE_RESP:
                // PROBERESP
                if ((guint)(data_end - data_cur) < sizeof(m_mgmt.u.probe_resp))
                    return false;
                g_memmove(&m_mgmt.u.probe_resp, data_cur, sizeof(m_mgmt.u.probe_resp));
                data_cur += sizeof(m_mgmt.u.probe_resp);
                
                break;
            case WLAN_FC_STYPE_BEACON:
                // BEACON
                if ((guint)(data_end - data_cur) < sizeof(m_mgmt.u.beacon))
                    return false;
                g_memmove(&m_mgmt.u.beacon, data_cur, sizeof(m_mgmt.u.beacon));
                data_cur += sizeof(m_mgmt.u.beacon);
                
                break;
            case WLAN_FC_STYPE_ATIM:
                // ATIM
                
                break;
            case WLAN_FC_STYPE_DISASSOC:
                // DISASSOC
                if ((guint)(data_end - data_cur) < sizeof(m_mgmt.u.disassoc))
                    return false;
                g_memmove(&m_mgmt.u.disassoc, data_cur, sizeof(m_mgmt.u.disassoc));
                data_cur += sizeof(m_mgmt.u.disassoc);
                
                break;
            case WLAN_FC_STYPE_AUTH:
                // AUTH
                if ((guint)(data_end - data_cur) < sizeof(m_mgmt.u.auth))
                    return false;
                g_memmove(&m_mgmt.u.auth, data_cur, sizeof(m_mgmt.u.auth));
                data_cur += sizeof(m_mgmt.u.auth);
                
                break;
            case WLAN_FC_STYPE_DEAUTH:
                // DEAUTH
                if ((guint)(data_end - data_cur) < sizeof(m_mgmt.u.deauth))
                    return false;
                g_memmove(&m_mgmt.u.deauth, data_cur, sizeof(m_mgmt.u.deauth));
                data_cur += sizeof(m_mgmt.u.deauth);
                
                break;
        }
        
        // Endpoints
        m_ep.dst = new c_ep_80211(m_mgmt.da);
        m_ep.net = new c_ep_80211(m_mgmt.bssid);
        m_ep.src = new c_ep_80211(m_mgmt.sa);
    
    } else if (mtype == WLAN_FC_TYPE_CTRL) {
    
        // Endpoints
        m_ep.dst = NULL;
        m_ep.net = NULL;
        m_ep.src = NULL;
        
        // Select subtype
        switch (stype) {
            case WLAN_FC_STYPE_PSPOLL:
                // PS-Poll
                if ((guint)(data_end - data_cur) < sizeof(m_ctrl_pspoll))
                    return false;
                g_memmove(&m_ctrl_pspoll, data_cur, sizeof(m_ctrl_pspoll));
                data_cur += sizeof(m_ctrl_pspoll);
                
                break;
            case WLAN_FC_STYPE_RTS:
                // RTS
                if ((guint)(data_end - data_cur) < sizeof(m_ctrl_rts))
                    return false;
                g_memmove(&m_ctrl_rts, data_cur, sizeof(m_ctrl_rts));
                data_cur += sizeof(m_ctrl_rts);
                
                break;
            case WLAN_FC_STYPE_CTS:
                // CTS
                if ((guint)(data_end - data_cur) < sizeof(m_ctrl_cts))
                    return false;
                g_memmove(&m_ctrl_cts, data_cur, sizeof(m_ctrl_cts));
                data_cur += sizeof(m_ctrl_cts);
                
                break;
            case WLAN_FC_STYPE_ACK:
                // ACK
                if ((guint)(data_end - data_cur) < sizeof(m_ctrl_ack))
                    return false;
                g_memmove(&m_ctrl_ack, data_cur, sizeof(m_ctrl_ack));
                data_cur += sizeof(m_ctrl_ack);
                
                break;
            case WLAN_FC_STYPE_CFEND:
                // CF-End
                if ((guint)(data_end - data_cur) < sizeof(m_ctrl_cfend))
                    return false;
                g_memmove(&m_ctrl_cfend, data_cur, sizeof(m_ctrl_cfend));
                data_cur += sizeof(m_ctrl_cfend);
                
                break;
            case WLAN_FC_STYPE_CFENDACK:
                // CF-End + CF-Ack
                if ((guint)(data_end - data_cur) < sizeof(m_ctrl_cfend))
                    return false;
                g_memmove(&m_ctrl_cfend, data_cur, sizeof(m_ctrl_cfend));
                data_cur += sizeof(m_ctrl_cfend);
                
                break;
        }
    
    } else if (mtype == WLAN_FC_TYPE_DATA) {
    
        // Header
	    if ((guint)(data_end - data_cur) < sizeof(m_hdr))
	        return false;
        g_memmove(&m_hdr, data_cur, sizeof(m_hdr));
        data_cur += sizeof(m_hdr);
    
        // Addr4
        if (WLAN_FC_GET_TODS(m_fc.frame_control) && WLAN_FC_GET_FROMDS(m_fc.frame_control)) {
            if ((guint)(data_end - data_cur) < sizeof(m_addr4))
                return false;
            g_memmove(m_addr4, data_cur, sizeof(m_addr4));
            data_cur += sizeof(m_addr4);
        }
        
        // QOS
        if (stype == WLAN_FC_STYPE_QOS_DATA || stype == WLAN_FC_STYPE_QOS_NULL) {
            if ((guint)(data_end - data_cur) < sizeof(m_qos))
                return false;
            g_memmove(&m_qos, data_cur, sizeof(m_qos));
            data_cur += sizeof(m_qos);
        }
        
        // LLC / SNAP handling
        if ((guint)(data_end - data_cur) < sizeof(m_snap))
            return false;
        g_memmove(&m_snap, data_cur, sizeof(m_snap));
        data_cur += sizeof(m_snap);
        
        // Endpoints
        bool to_ds = WLAN_FC_GET_TODS(m_fc.frame_control);
        bool from_ds = WLAN_FC_GET_FROMDS(m_fc.frame_control);
        if (!to_ds && !from_ds) {
            // ToDS=0 && FromDS=0
            m_ep.dst = new c_ep_80211(m_hdr.addr1); // RA = DA
            m_ep.src = new c_ep_80211(m_hdr.addr2); // TA = SA
            m_ep.net = new c_ep_80211(m_hdr.addr3); // BSSID
        } else if (!to_ds && from_ds) {
            // ToDS=0 && FromDS=1
            m_ep.dst = new c_ep_80211(m_hdr.addr1); // RA = DA
            m_ep.net = new c_ep_80211(m_hdr.addr2); // TA = BSSID
            m_ep.src = new c_ep_80211(m_hdr.addr3); // SA
        } else if (to_ds && !from_ds) {
            // ToDS=1 && FromDS=0
            m_ep.net = new c_ep_80211(m_hdr.addr1); // RA = BSSID
            m_ep.src = new c_ep_80211(m_hdr.addr2); // TA = SA
            m_ep.dst = new c_ep_80211(m_hdr.addr3); // DA
        } else {
            // ToDS=1 && FromDS=1
            m_ep.dst = new c_ep_80211(m_hdr.addr3); // DA
            m_ep.src = new c_ep_80211(m_addr4); // SA
            m_ep.net = NULL;
        }
        
        // Next layer
        next_layer = true;
    }
    
    // Free data
    g_byte_array_remove_range(data, 0, data_cur - data->data);

    // Debug
    /*
    if (mtype == WLAN_FC_TYPE_DATA) {
        g_message("[pck] <========================================================================>");
        str_dump();
        c_util::hex_log("[pck] layer-80211 hexdump!", data->data, data->len);
    }
    */

    // Node
    m_node = g_node_new(this);
    g_assert(node);
    g_node_append(m_node, node);

    // Next layer
    if (next_layer) {
        switch (m_snap.snap_type) {
            case LLC_TYPE_IPV4:
                {
                    c_layer_ipv4* next = new c_layer_ipv4();
                    if (!next->init_unpack(m_node, data))
                        delete next;
                }
                break;
            case LLC_TYPE_IPV6:
                {
                    c_layer_ipv6* next = new c_layer_ipv6();
                    if (!next->init_unpack(m_node, data))
                        delete next;
                }
                break;
        }
    }
    
    // Activate and return
    m_active = true;
    return true;
}

/*
bool c_layer_80211::init_pack(GNode* node, GByteArray* data, c_layer* ref)
{
    // Check
    g_assert(!m_active);
    
    // Check layer type
    if (ref->type() != this->type())
        return false;
    
    // Reference
    c_layer_80211* ref_c = (c_layer_80211*) ref;
    
    // Type and subtype
    guint mtype = WLAN_FC_GET_TYPE(ref_c->m_fc.frame_control);
    guint stype = WLAN_FC_GET_STYPE(ref_c->m_fc.frame_control);

    // Only data frames
    if (mtype != WLAN_FC_TYPE_DATA)
        return false;
    
    // Copy
    g_memmove(&m_hdr, &(ref_c->m_hdr), sizeof(m_hdr));
    g_memmove(&m_addr4, &(ref_c->m_hdr), sizeof(m_addr4));
    
    // Header
    m_hdr.frame_control = WLAN_FC_CONSTRUCT(WLAN_FC_TYPE_DATA, WLAN_FC_STYPE_DATA);
    m_hdr.duration = 0;
    m_hdr.seq_ctrl = WLAN_SEQ_CONSTRUCT(0, WLAN_SEQ_GET_SEQ(ref_c->m_hdr.seq_ctrl) + 1);
}
*/

void c_layer_80211::end()
{
    // Check
    g_assert(m_active);
    
    // Endpoints
    if (m_ep.src)
        delete m_ep.src;
    if (m_ep.dst)
        delete m_ep.dst;
    if (m_ep.net)
        delete m_ep.net;
    
    // Deactivate
    m_active = false;
}

// Output
void c_layer_80211::str_dump()
{
    // Check
    g_assert(m_active);
    
    // Frame control header
    g_message("[pck] layer-80211:");
    g_message("[pck] * version=%u, type=%u, subtype=%u, to_ds=%u, from_ds=%u",
        WLAN_FC_GET_PVER(m_fc.frame_control),
        WLAN_FC_GET_TYPE(m_fc.frame_control), WLAN_FC_GET_STYPE(m_fc.frame_control),
        WLAN_FC_GET_TODS(m_fc.frame_control), WLAN_FC_GET_FROMDS(m_fc.frame_control)
    );
    g_message("[pck] * more_frag=%u, retry=%u, pwrmgmt=%u, more_data=%u, wep=%u, order=%u",
        WLAN_FC_GET_MOREFRAG(m_fc.frame_control), WLAN_FC_GET_RETRY(m_fc.frame_control),
        WLAN_FC_GET_PWRMGT(m_fc.frame_control), WLAN_FC_GET_MOREDATA(m_fc.frame_control),
        WLAN_FC_GET_ISWEP(m_fc.frame_control), WLAN_FC_GET_ORDER(m_fc.frame_control)
    );
    g_message("[pck] * duration_id=%u", m_fc.duration_id);
    
    // Select type
    guint mtype = WLAN_FC_GET_TYPE(m_fc.frame_control);
    guint stype = WLAN_FC_GET_STYPE(m_fc.frame_control);
    if (mtype == WLAN_FC_TYPE_MGMT) {
    
        // Management header
        g_message("[pck] * sa=[%02x%02x%02x%02x%02x%02x], da=[%02x%02x%02x%02x%02x%02x], bssid=[%02x%02x%02x%02x%02x%02x]",
            m_mgmt.sa[0], m_mgmt.sa[1], m_mgmt.sa[2], m_mgmt.sa[3], m_mgmt.sa[4], m_mgmt.sa[5],
            m_mgmt.da[0], m_mgmt.da[1], m_mgmt.da[2], m_mgmt.da[3], m_mgmt.da[4], m_mgmt.da[5],
            m_mgmt.bssid[0], m_mgmt.bssid[1], m_mgmt.bssid[2], m_mgmt.bssid[3], m_mgmt.bssid[4], m_mgmt.bssid[5]
        );
        
        // Select subtype
        switch(stype) {
            case WLAN_FC_STYPE_ASSOC_REQ:
                // ASSOCREQ
                
                break;
            case WLAN_FC_STYPE_ASSOC_RESP:
                // ASSOCRESP
                
                break;
            case WLAN_FC_STYPE_REASSOC_REQ:
                // REASSOCREQ
                
                break;
            case WLAN_FC_STYPE_REASSOC_RESP:
                // REASSOCRESP
                
                break;
            case WLAN_FC_STYPE_PROBE_REQ:
                // PROBEREQ
                
                break;
            case WLAN_FC_STYPE_PROBE_RESP:
                // PROBERESP
                
                break;
            case WLAN_FC_STYPE_BEACON:
                // BEACON
                
                break;
            case WLAN_FC_STYPE_ATIM:
                // ATIM
                
                break;
            case WLAN_FC_STYPE_DISASSOC:
                // DISASSOC
                
                break;
            case WLAN_FC_STYPE_AUTH:
                // AUTH
                
                break;
            case WLAN_FC_STYPE_DEAUTH:
                // DEAUTH
                
                break;
        }
    
    } else if (mtype == WLAN_FC_TYPE_CTRL) {
        
        // Select subtype
        switch (stype) {
            case WLAN_FC_STYPE_PSPOLL:
                // PS-Poll
                
                break;
            case WLAN_FC_STYPE_RTS:
                // RTS
                
                break;
            case WLAN_FC_STYPE_CTS:
                // CTS
                
                break;
            case WLAN_FC_STYPE_ACK:
                // ACK
                
                break;
            case WLAN_FC_STYPE_CFEND:
                // CF-End
                
                break;
            case WLAN_FC_STYPE_CFENDACK:
                // CF-End + CF-Ack
                
                break;
        }
    
    } else if (mtype == WLAN_FC_TYPE_DATA) {
    
        // Header
        g_message("[pck] * mac1=[%02x%02x%02x%02x%02x%02x], mac2=[%02x%02x%02x%02x%02x%02x], mac3=[%02x%02x%02x%02x%02x%02x]",
            m_hdr.addr1[0], m_hdr.addr1[1], m_hdr.addr1[2], m_hdr.addr1[3], m_hdr.addr1[4], m_hdr.addr1[5],
            m_hdr.addr2[0], m_hdr.addr2[1], m_hdr.addr2[2], m_hdr.addr2[3], m_hdr.addr2[4], m_hdr.addr2[5],
            m_hdr.addr3[0], m_hdr.addr3[1], m_hdr.addr3[2], m_hdr.addr3[3], m_hdr.addr3[4], m_hdr.addr3[5]
        );
    
        // Addr4
        if (WLAN_FC_GET_TODS(m_fc.frame_control) && WLAN_FC_GET_FROMDS(m_fc.frame_control)) {
            g_message("[pck] * mac4=[%02x%02x%02x%02x%02x%02x]",
                m_addr4[0], m_addr4[1], m_addr4[2], m_addr4[3], m_addr4[4], m_addr4[5]
            );
        }
        
        // QOS
        if (stype == WLAN_FC_STYPE_QOS_DATA || stype == WLAN_FC_STYPE_QOS_NULL) {
            g_message("[pck] * qos: priority=%u, eosp=%u, ack_policy=%u", m_qos.priority, m_qos.eosp, m_qos.ackpol);
        }
        
        // LLC / SNAP handling
        g_message("[pck] * llc: type_hex=%04x, type_str=%s",
            m_snap.snap_type,
            (m_snap.snap_type == LLC_TYPE_IPV4 ? "ipv4" :
            (m_snap.snap_type == LLC_TYPE_IPV6 ? "ipv6" :
            (m_snap.snap_type == LLC_TYPE_ARP ? "arp" : "unknown")))
        );
    }
}

const gchar* c_layer_80211::str_name()
{
    // Check
    g_assert(m_active);
    
    // String
    return "802.11";
}

const gchar* c_layer_80211::str_value()
{
    // Check
    g_assert(m_active);
    
    // String
    switch (WLAN_FC_GET_TYPE(m_fc.frame_control)) {
        case WLAN_FC_TYPE_MGMT: return "Management frame";
        case WLAN_FC_TYPE_CTRL: return "Control frame";
        case WLAN_FC_TYPE_DATA: return "Data frame";
        default: return "Unknown frame";
    }
}

