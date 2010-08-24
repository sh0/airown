/*
 * Airown - packet handling
 *
 * Copyright (C) 2010 sh0 <sh0@yutani.ee>
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
#include "ao_main.h"
#include "ao_util.h"
#include "ao_payload.h"
#include "pk_packet.h"
#include "pk_layer2.h"
#include "pk_layer3.h"
#include "pk_layer4.h"

// Main packet handler
void ao_pck_loop(lorcon_t* context, lorcon_packet_t* packet, u_char* user)
{
    // Packet
    st_ao_packet pck;
    memset(&pck, 0, sizeof(pck));
    
    // Airown
    pck.ao_inst = (st_ao_inst*) user;
    
    // Lorcon
    pck.lor_ctx = context;
    pck.lor_pck = packet;
    
    // Layers
    pck.m2_type = AO_M2_NONE;
    pck.m3_type = AO_M3_NONE;
    pck.m4_type = AO_M4_NONE;

    // Currently only ieee80211
    pck.m2_data = (guint8*) packet->packet_header;
    pck.m2_size = packet->length_header;
    pck_ieee80211_read(&pck);
    
    // Log
    ao_pck_log(&pck);
    
    // Payload
    ao_payload_pck(&pck);
    
    // Free
    pck_ieee80211_free(&pck);
    
    // Free packet
	lorcon_packet_free(packet);
}

void ao_pck_log(st_ao_packet* pck)
{
    // Filter
    guint32 dmask = pck->ao_inst->dbg_mask;
    guint32 dshow = pck->ao_inst->dbg_show;
    guint32 ddump = pck->ao_inst->dbg_dump;
    if (!(
            ((dmask & AO_PROTO_L2_IEEE80211) && (pck->m2_type == AO_M2_IEEE80211)) ||
            ((dmask & AO_PROTO_L3_IPV4) && (pck->m3_type == AO_M3_IPV4)) ||
            ((dmask & AO_PROTO_L3_IPV6) && (pck->m3_type == AO_M3_IPV6)) ||
            ((dmask & AO_PROTO_L3_ARP) && (pck->m4_type == AO_M3_ARP)) ||
            ((dmask & AO_PROTO_L4_TCP) && (pck->m4_type == AO_M4_TCP)) ||
            ((dmask & AO_PROTO_L4_UDP) && (pck->m4_type == AO_M4_UDP)) ||
            ((dmask & AO_PROTO_L5_PAYLOAD) && (pck->pl_size > 0))
        ))
        return;

    // Debug
    printf("<====================================================================>\n");

    // General
    printf("* pck! iface=%s, driver=%s, size=%d, channel=%d\n",
        lorcon_get_capiface(pck->lor_ctx),
        lorcon_get_driver_name(pck->lor_ctx),
        pck->lor_pck->length_header, pck->lor_pck->channel);
    
    // Layer 2
    if ((pck->m2_type == AO_M2_IEEE80211) && (dshow & AO_PROTO_L2_IEEE80211)) {
    
        struct ieee80211_hdr* iw = pck->m2.dot11.iw;
        g_print("* ieee! version=%u, type=%u, subtype=%u, to_ds=%u, from_ds=%u\n",
            iw->u1.fc.version,
            iw->u1.fc.type, iw->u1.fc.subtype,
            iw->u1.fc.to_ds, iw->u1.fc.from_ds);
        g_print("* ieee! more_frag=%u, retry=%u, pwrmgmt=%u, more_data=%u, wep=%u, order=%u\n",
            iw->u1.fc.more_frag, iw->u1.fc.retry, iw->u1.fc.pwrmgmt, iw->u1.fc.more_data, iw->u1.fc.wep, iw->u1.fc.order);
        g_print("* ieee! mac1=%02x%02x%02x%02x%02x%02x, mac2=%02x%02x%02x%02x%02x%02x, mac3=%02x%02x%02x%02x%02x%02x\n",
            iw->addr1[0], iw->addr1[1], iw->addr1[2], iw->addr1[3], iw->addr1[4], iw->addr1[5],
            iw->addr2[0], iw->addr2[1], iw->addr2[2], iw->addr2[3], iw->addr2[4], iw->addr2[5],
            iw->addr3[0], iw->addr3[1], iw->addr3[2], iw->addr3[3], iw->addr3[4], iw->addr3[5]
        );
        if (pck->m2.dot11.addr4) {
            g_print("* ieee! mac4=%02x%02x%02x%02x%02x%02x\n",
                pck->m2.dot11.addr4[0], pck->m2.dot11.addr4[1], pck->m2.dot11.addr4[2],
                pck->m2.dot11.addr4[3], pck->m2.dot11.addr4[4], pck->m2.dot11.addr4[5]
            );
        }
        if (pck->m2.dot11.qos) {
            g_print("* qos!\n");
        }
        if (pck->m2.dot11.llc) {
            g_print("* llc! type=%u, is_ipv4=%u, is_ipv6=%u, is_arp=%u\n",
                pck->m2.dot11.llc->snap_type,
                pck->m2.dot11.llc->snap_type == LLC_TYPE_IPV4 ? 1 : 0,
                pck->m2.dot11.llc->snap_type == LLC_TYPE_IPV6 ? 1 : 0,
                pck->m2.dot11.llc->snap_type == LLC_TYPE_ARP ? 1 : 0
            );
        }
    }
    if ((pck->m2_size > 0) && (
        (ddump & AO_PROTO_L2_IEEE80211)
        )) {
        dumphex(pck->m2_data, pck->m2_size);
    }

    // Layer 3
    if ((pck->m3_type == AO_M3_IPV4) && (dshow & AO_PROTO_L3_IPV4)) {
        g_print("* ipv4! proto=%u, is_tcp=%u, is_udp=%u, src=%u.%u.%u.%u, dst=%u.%u.%u.%u\n",
            pck->m3.ipv4.hdr->ip_p,
            pck->m3.ipv4.hdr->ip_p == IPPROTO_TCP ? 1 : 0,
            pck->m3.ipv4.hdr->ip_p == IPPROTO_UDP ? 1 : 0,
            (pck->m3.ipv4.hdr->ip_src.s_addr) & 0xff, (pck->m3.ipv4.hdr->ip_src.s_addr >> 8) & 0xff, (pck->m3.ipv4.hdr->ip_src.s_addr >> 16) & 0xff, (pck->m3.ipv4.hdr->ip_src.s_addr >> 24) & 0xff,
            (pck->m3.ipv4.hdr->ip_dst.s_addr) & 0xff, (pck->m3.ipv4.hdr->ip_dst.s_addr >> 8) & 0xff, (pck->m3.ipv4.hdr->ip_dst.s_addr >> 16) & 0xff, (pck->m3.ipv4.hdr->ip_dst.s_addr >> 24) & 0xff);
    } else if ((pck->m3_type == AO_M3_IPV6) && (dshow & AO_PROTO_L3_IPV6)) {
        g_print("* ipv6! proto=%u, is_tcp=%u, is_udp=%u\n",
            pck->m3.ipv6.hdr->ip_nh,
            pck->m3.ipv6.hdr->ip_nh == IPPROTO_TCP ? 1 : 0,
            pck->m3.ipv6.hdr->ip_nh == IPPROTO_UDP ? 1 : 0
        );
        guint16* saddr = pck->m3.ipv6.hdr->ip_src.__u6_addr.__u6_addr16;
        guint16* daddr = pck->m3.ipv6.hdr->ip_dst.__u6_addr.__u6_addr16;
        g_print("* ipv6! src=%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x\n",
            saddr[0], saddr[1], saddr[2], saddr[3], saddr[4], saddr[5], saddr[6], saddr[7]
        );
        g_print("* ipv6! dst=%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x\n",
            daddr[0], daddr[1], daddr[2], daddr[3], daddr[4], daddr[5], daddr[6], daddr[7]
        );
    }
    if ((pck->m3_size > 0) && (
        (ddump & AO_PROTO_L3_IPV4) || (ddump & AO_PROTO_L3_IPV6) || (ddump & AO_PROTO_L3_ARP)
        )) {
        dumphex(pck->m3_data, pck->m3_size);
    }
    
    // Layer 4
    if ((pck->m4_type == AO_M4_TCP) && (dshow & AO_PROTO_L4_TCP)) {
        g_print("* tcp! port_src=%hu, port_dst=%hu, checksum=0x%04x, len=%hu\n",
            ntohs(pck->m4.tcp.hdr->source), ntohs(pck->m4.tcp.hdr->dest),
            ntohs(pck->m4.tcp.hdr->check), pck->m4.tcp.hdr->doff * 4
        );
        g_print("* tcp! res_seq=0x%08x, ack_seq=0x%08x, fin=%u, syn=%u, rst=%u, psh=%u, ack=%u, urg=%u\n", //, ece=%u, cwr=%u
            ntohl(pck->m4.tcp.hdr->seq), ntohl(pck->m4.tcp.hdr->ack_seq),
            pck->m4.tcp.hdr->fin, pck->m4.tcp.hdr->syn, pck->m4.tcp.hdr->rst, pck->m4.tcp.hdr->psh, pck->m4.tcp.hdr->ack, pck->m4.tcp.hdr->urg
            //pck->m4.tcp.hdr->ece, pck->m4.tcp.hdr->cwr
        );
        if (pck->m4.tcp.ts) {
            g_print("* tcp! time_a=0x%08x, time_b=0x%08x\n", ntohl(pck->m4.tcp.ts->time_a), ntohl(pck->m4.tcp.ts->time_b));
        }
    } else if ((pck->m4_type == AO_M4_UDP) && (dshow & AO_PROTO_L4_UDP)) {
        g_print("* udp! port_src=%hu, port_dst=%hu, checksum=0x%04x, len=%hu\n",
            ntohs(pck->m4.udp.hdr->source), ntohs(pck->m4.udp.hdr->dest),
            ntohs(pck->m4.udp.hdr->check), ntohs(pck->m4.udp.hdr->len)
        );
    }
    if ((pck->m4_size > 0) && (
        (ddump & AO_PROTO_L4_TCP) || (ddump & AO_PROTO_L4_UDP)
        )) {
        dumphex(pck->m4_data, pck->m4_size);
    }
    
    // Layer 5
    if (dshow & AO_PROTO_L5_PAYLOAD) {
        g_print("* payload! size=%u\n", pck->pl_size);
    }
    if ((pck->pl_size > 0) && (ddump & AO_PROTO_L5_PAYLOAD)) {
        dumphex(pck->pl_data, pck->pl_size);
    }
    
    // Ending
    //printf("\n");
}

