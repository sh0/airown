/*
 * Airown - TCP layer
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
#include "pck_tcp.h"

// <===> TCP endpoint <========================================================>

// Constructor and destructor
c_ep_tcp::c_ep_tcp(guint16 port)
{
    m_str = NULL;
    m_port = port;
}

c_ep_tcp::c_ep_tcp(c_ep_tcp* ep_b)
{
    m_str = NULL;
    c_ep_tcp* ep_c = dynamic_cast<c_ep_tcp*>(ep_b);
    m_port = ep_c->m_port;
}

c_ep_tcp::~c_ep_tcp()
{
    if (m_str)
        g_free(m_str);
}

// Types
guint c_ep_tcp::cast()
{
    return EP_CAST_NONE;
}

// Compare
bool c_ep_tcp::cmp(c_ep* ep_b)
{
    c_ep_tcp* ep_c = dynamic_cast<c_ep_tcp*>(ep_b);
    return (m_port == ep_c->m_port ? true : false);
}

// Output
void c_ep_tcp::str_dump()
{
    g_message("[pck] ep-tcp -> port=%u", m_port);
}

const gchar* c_ep_tcp::str_name()
{
    return "TCP";
}

const gchar* c_ep_tcp::str_value()
{
    if (!m_str)
        m_str = g_strdup_printf("%u", m_port);
    return m_str;
}

// <===> TCP layer <===========================================================>

// Constructor and destructor
c_layer_tcp::c_layer_tcp()
{
    // Deactive
    m_active = false;
}

c_layer_tcp::~c_layer_tcp()
{
    // End
    if (m_active)
        end();
}

// Init and end
bool c_layer_tcp::init_unpack(GNode* node, GByteArray* data)
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

    // Header size
    guint hdrlen = 4 * m_hdr.th_off;
    if (data_end - data_cur < hdrlen - (gint)sizeof(m_hdr))
        return false;
    
    // Options
    guint optlen = hdrlen - sizeof(m_hdr);
    for (guint i=0; i<optlen; ) {
        // Kind and length
        if (i + 2 > optlen)
            break;
        guint8 o_kind = data_cur[i++];
        guint8 o_len = data_cur[i++];
        
        // Data
        if (i + o_len > optlen)
            break;
            
        // Kind select
        if (o_kind == 0) {
            // End of options
            break;
        } else if (o_kind == 1) {
            // Nop
            continue;
        } else {
            // Unknown
            break;
        }
    }
    data_cur += optlen;
    
    // Checksum
    // TODO

    // Endpoints
    m_ep.src = new c_ep_tcp(g_ntohs(m_hdr.th_sport));
    m_ep.dst = new c_ep_tcp(g_ntohs(m_hdr.th_dport));
    m_ep.net = NULL;
    
    // Free data
    g_byte_array_remove_range(data, 0, data_cur - data->data);

    // Debug    
    g_message("[pck] <========================================================================>");
    str_dump();
    c_util::hex_log("[pck] layer-tcp hexdump!", data->data, data->len);
    
    // Node
    m_node = g_node_new(this);
    g_assert(node);
    g_node_append(m_node, node);

    // Assembler layer

    // Return
    m_active = true;
    return true;
}

void c_layer_tcp::end()
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
void c_layer_tcp::str_dump()
{
    // Check
    //g_assert(m_active);
    
    // Message
    GPtrArray* fg_arr = g_ptr_array_new();
    if (m_hdr.th_flags & TH_URG)
        g_ptr_array_add(fg_arr, (gpointer) "URG");
    if (m_hdr.th_flags & TH_ACK)
        g_ptr_array_add(fg_arr, (gpointer) "ACK");
    if (m_hdr.th_flags & TH_PUSH)
        g_ptr_array_add(fg_arr, (gpointer) "PSH");
    if (m_hdr.th_flags & TH_RST)
        g_ptr_array_add(fg_arr, (gpointer) "RST");
    if (m_hdr.th_flags & TH_SYN)
        g_ptr_array_add(fg_arr, (gpointer) "SYN");
    if (m_hdr.th_flags & TH_FIN)
        g_ptr_array_add(fg_arr, (gpointer) "FIN");
    g_ptr_array_add(fg_arr, NULL);
    gchar* fg_join = g_strjoinv(",", (gchar**) fg_arr->pdata);
    g_message(
        "[pck] layer-tcp: flags=[%s], src=%s, dst=%s",
        fg_join,
        m_ep.src->str_value(), m_ep.dst->str_value()
    );
    g_free(fg_join);
    g_ptr_array_unref(fg_arr);
}

const gchar* c_layer_tcp::str_name()
{
    // Check
    g_assert(m_active);
    
    // String
    return "TCP";
}

const gchar* c_layer_tcp::str_value()
{
    // Check
    g_assert(m_active);
    
    // String
    return "Data frame";
}

// Functions
#if 0
void pck_tcp_read(st_ao_packet* pck)
{
    if (pck->m4_size >= sizeof(struct libnet_tcp_hdr)) {
        // Header
        pck->m4.tcp.hdr = (struct libnet_tcp_hdr*) pck->m4_data;
        
        // Lengths and offsets
        guint16 tcp_len = 0;
        if (pck->m3_type == AO_M3_IPV4) {
            tcp_len = ntohs(pck->m3.ipv4.hdr->ip_len) - (pck->m3.ipv4.hdr->ip_hl * 4) - (pck->m4.tcp.hdr->th_off * 4);
        } else if (pck->m3_type == AO_M3_IPV6) {
            tcp_len = ntohs(pck->m3.ipv4.hdr->ip_len) - sizeof(struct libnet_ipv6_hdr) - (pck->m4.tcp.hdr->th_off * 4);
        } else {
            return;
        }
        gint32 tcp_off = (gint32)(pck->m4.tcp.hdr->th_off * 4) - sizeof(struct libnet_tcp_hdr);
        if (tcp_off < 0 || tcp_off + tcp_len > pck->m4_size) {
            //printf("* tcph! offset/size problem! tcp_len=%u, tcp_off=%d, tcp_size=%u\n", tcp_len, tcp_off, pck->m4_size);
            return;
        }
        
        // Options
        pck->m4.tcp.ts = NULL;
        gint32 opt_len = (pck->m4.tcp.hdr->th_off * 4) - 20;
        //g_print("[dbg] opt_len=%d\n", opt_len);
        if (opt_len > 0) {
            guint8* opt_ptr = pck->m4_data + 20;
            guint32 opt_off = 0;
            while (opt_off < opt_len) {
                if (opt_len > opt_off + 9 && *(opt_ptr + opt_off + 0) == 0x08 && *(opt_ptr + opt_off + 1) == 0x0a) {
                    //g_print("[dbg] opt=ts\n");
                    pck->m4.tcp.ts = (st_tcp_timestamp*) (opt_ptr + opt_off + 2);
                    opt_off += 10;
                } else if (*(opt_ptr + opt_off) == 0) {
                    //g_print("[dbg] opt=end\n");
                    opt_off += 1;
                    break;
                } else {
                    //g_print("[dbg] opt=nop\n");
                    opt_off += 1;
                }
            }
        }
        
        // Set payload
        pck->pl_data = pck->m4_data + sizeof(struct libnet_tcp_hdr) + tcp_off;
        pck->pl_size = tcp_len;
    }
}
#endif

