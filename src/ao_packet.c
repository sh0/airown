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
#include "ao_packet.h"
#include "ao_util.h"
#include "ao_content.h"
#include "ao_payload.h"

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
    ao_pck_ieee80211_read(&pck);
    
    // Log
    ao_pck_log(&pck);
    
    // Content
    //ctx_tcp_proc(&pck);
    
    // Payload
    ao_payload_pck(&pck);
    
    // Free
    ao_pck_ieee80211_free(&pck);
    
    /*
    // Dot3 conversion
	u_char* dot3;
	int len = lorcon_packet_to_dot3(packet, &dot3);
	printf("dot3 length %d\n", len);
	free(dot3);
    */
    
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
                pck->m2.dot11.llc->type,
                pck->m2.dot11.llc->type == LLC_TYPE_IPV4 ? 1 : 0,
                pck->m2.dot11.llc->type == LLC_TYPE_IPV6 ? 1 : 0,
                pck->m2.dot11.llc->type == LLC_TYPE_ARP ? 1 : 0
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
            pck->m3.ipv4.hdr->protocol,
            pck->m3.ipv4.hdr->protocol == IPPROTO_TCP ? 1 : 0,
            pck->m3.ipv4.hdr->protocol == IPPROTO_UDP ? 1 : 0,
            (pck->m3.ipv4.hdr->saddr) & 0xff, (pck->m3.ipv4.hdr->saddr >> 8) & 0xff, (pck->m3.ipv4.hdr->saddr >> 16) & 0xff, (pck->m3.ipv4.hdr->saddr >> 24) & 0xff,
            (pck->m3.ipv4.hdr->daddr) & 0xff, (pck->m3.ipv4.hdr->daddr >> 8) & 0xff, (pck->m3.ipv4.hdr->daddr >> 16) & 0xff, (pck->m3.ipv4.hdr->daddr >> 24) & 0xff);
    } else if ((pck->m3_type == AO_M3_IPV6) && (dshow & AO_PROTO_L3_IPV6)) {
        g_print("* ipv6! proto=%u, is_tcp=%u, is_udp=%u\n",
            pck->m3.ipv6.hdr->nexthdr,
            pck->m3.ipv6.hdr->nexthdr == IPPROTO_TCP ? 1 : 0,
            pck->m3.ipv6.hdr->nexthdr == IPPROTO_UDP ? 1 : 0
        );
        guint16* saddr = pck->m3.ipv6.hdr->saddr.s6_addr16;
        guint16* daddr = pck->m3.ipv6.hdr->daddr.s6_addr16;
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

void ao_pck_ieee80211_read(st_ao_packet* pck)
{
    // Size check
	if (pck->m2_size >= sizeof(struct ieee80211_hdr)) {
	
	    // Set type
	    pck->m2_type = AO_M2_IEEE80211;
	    
	    // Ieee80211 header
	    guint32 hdr_offset = sizeof(struct ieee80211_hdr);
	    pck->m2.dot11.iw = (struct ieee80211_hdr*) pck->m2_data;
	    
	    // Data packets
	    if (pck->m2.dot11.iw->u1.fc.type == WLAN_FC_TYPE_DATA) {
	    
	        // Addr4
	        pck->m2.dot11.addr4 = NULL;
	        if ((
	                pck->m2.dot11.iw->u1.fc.to_ds && pck->m2.dot11.iw->u1.fc.from_ds
	            ) && (
	                pck->m2_size >= hdr_offset + 6
	            )) {
	            pck->m2.dot11.addr4 = (uint8_t*)(pck->m2_data + hdr_offset);
	            hdr_offset += 6;
	        }
	        
	        // QOS
	        pck->m2.dot11.qos = NULL;
	        if ((
	                pck->m2.dot11.iw->u1.fc.subtype == WLAN_FC_SUBTYPE_QOSDATA ||
	                pck->m2.dot11.iw->u1.fc.subtype == WLAN_FC_SUBTYPE_QOSNULL
	            ) && (
	                pck->m2_size >= hdr_offset + sizeof(struct ieee80211_qos)
	            )) {
	            pck->m2.dot11.qos = (struct ieee80211_qos*)(pck->m2_data + hdr_offset);
	            hdr_offset += sizeof(struct ieee80211_qos);
	        }
	        
	        // LLC
	        pck->m2.dot11.llc = NULL;
	        if (pck->m2_size >= hdr_offset + sizeof(struct llc_hdr)) {
	            pck->m2.dot11.llc = (struct llc_hdr*)(pck->m2_data + hdr_offset);
	            hdr_offset += sizeof(struct llc_hdr);
	        }
	        
	        // Next layer
	        if (pck->m2.dot11.llc != NULL) {
	        
	            // Data
	            pck->m3_data = pck->m2_data + hdr_offset;
	            pck->m3_size = pck->m2_size - hdr_offset;
	        
	            // Process
	            switch (pck->m2.dot11.llc->type) {
	                case LLC_TYPE_IPV4:
	                    ao_pck_ipv4_read(pck);
	                    break;
	                case LLC_TYPE_IPV6:
	                    ao_pck_ipv6_read(pck);
	                    break;
	            }
	                
		    }
		    
	    }
	}
}

void ao_pck_ieee80211_free(st_ao_packet* pck)
{
    switch (pck->m3_type) {
        case AO_M3_IPV4:
            ao_pck_ipv4_free(pck);
            break;
        case AO_M3_IPV6:
            ao_pck_ipv6_free(pck);
            break;
    }
}

void ao_pck_ipv4_read(st_ao_packet* pck)
{
    // IPv4 header
    pck->m3.ipv4.hdr = NULL;
    if (pck->m3_size >= sizeof(struct iphdr)) {
    
        // Set type
        pck->m3_type = AO_M3_IPV4;
        
        // Header
        pck->m3.ipv4.hdr = (struct iphdr*)(pck->m3_data);
        
        // Data
        pck->m4_data = pck->m3_data + sizeof(struct iphdr);
        pck->m4_size = pck->m3_size - sizeof(struct iphdr);
        
        // Next layer
        switch (pck->m3.ipv4.hdr->protocol) {
            case IPPROTO_TCP:
                ao_pck_tcp_read(pck);
                break;
            case IPPROTO_UDP:
                ao_pck_udp_read(pck);
                break;
        }
    }
}

void ao_pck_ipv4_free(st_ao_packet* pck)
{
    switch (pck->m4_type) {
        case AO_M4_TCP:
            ao_pck_tcp_free(pck);
            break;
        case AO_M4_UDP:
            ao_pck_udp_free(pck);
            break;
    }
}

void ao_pck_ipv6_read(st_ao_packet* pck)
{
    // IPv6 header
    pck->m3.ipv6.hdr = NULL;
    if (pck->m3_size >= sizeof(struct ipv6hdr)) {
    
        // Set type
        pck->m3_type = AO_M3_IPV6;
        
        // Header
        pck->m3.ipv6.hdr = (struct ipv6hdr*)(pck->m3_data);
        
        // Data
        pck->m4_data = pck->m3_data + sizeof(struct ipv6hdr);
        pck->m4_size = pck->m3_size - sizeof(struct ipv6hdr);
        
        // Next layer
        switch (pck->m3.ipv6.hdr->nexthdr) {
            case IPPROTO_TCP:
                ao_pck_tcp_read(pck);
                break;
            case IPPROTO_UDP:
                ao_pck_udp_read(pck);
                break;
        }
    }
}

void ao_pck_ipv6_free(st_ao_packet* pck)
{
    switch (pck->m4_type) {
        case AO_M4_TCP:
            ao_pck_tcp_free(pck);
            break;
        case AO_M4_UDP:
            ao_pck_udp_free(pck);
            break;
    }
}

void ao_pck_tcp_read(st_ao_packet* pck)
{
    if (pck->m4_size >= sizeof(struct tcphdr)) {
        // Header
        pck->m4.tcp.hdr = (struct tcphdr*) pck->m4_data;
        
        // Lengths and offsets
        guint16 tcp_len = 0;
        if (pck->m3_type == AO_M3_IPV4) {
            tcp_len = ntohs(pck->m3.ipv4.hdr->tot_len) - (pck->m3.ipv4.hdr->ihl * 4) - (pck->m4.tcp.hdr->doff * 4);
        } else if (pck->m3_type == AO_M3_IPV6) {
            tcp_len = ntohs(pck->m3.ipv4.hdr->tot_len) - sizeof(struct ipv6hdr) - (pck->m4.tcp.hdr->doff * 4);
        } else {
            return;
        }
        gint32 tcp_off = (gint32)(pck->m4.tcp.hdr->doff * 4) - sizeof(struct tcphdr);
        if (tcp_off < 0 || tcp_off + tcp_len > pck->m4_size) {
            //printf("* tcph! offset/size problem! tcp_len=%u, tcp_off=%d, tcp_size=%u\n", tcp_len, tcp_off, pck->m4_size);
            return;
        }
        
        // Options
        pck->m4.tcp.ts = NULL;
        gint32 opt_len = (pck->m4.tcp.hdr->doff * 4) - 20;
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
        pck->pl_data = pck->m4_data + sizeof(struct tcphdr) + tcp_off;
        pck->pl_size = tcp_len;
        
        // Set type
        pck->m4_type = AO_M4_TCP;
        
        /*
        // Temporary inject
        if ((tcp_len > 4) && (*((uint32_t*)tcp_data) == 0x20544547)) { //0x47455420
            ao_spoof(context, hdr_w, hdr_llc, hdr_ip, hdr_tcp, tcp_data, tcp_len);
        }
        //dumphex((uint8_t*) tcp_data, tcp_len);
        */
    }
}

void ao_pck_tcp_free(st_ao_packet* pck)
{

}

void ao_pck_udp_read(st_ao_packet* pck)
{
    if (pck->m4_size >= sizeof(struct udphdr)) {
        // Header
        pck->m4.udp.hdr = (struct udphdr*) pck->m4_data;
        
        // Lengths and offsets
        guint16 udp_len = ntohs(pck->m4.udp.hdr->len);
        if (udp_len > pck->m4_size) {
            return;
        }
        
        // Set payload
        pck->pl_data = pck->m4_data + sizeof(struct udphdr);
        pck->pl_size = udp_len - sizeof(struct udphdr);
        
        // Set type
        pck->m4_type = AO_M4_UDP;
    }
}

void ao_pck_udp_free(st_ao_packet* pck)
{

}

void ao_inj_temp(
    lorcon_t* context,
    struct ieee80211_hdr* hdr_w,
    struct llc_hdr* hdr_llc,
    struct iphdr* hdr_ip, 
    struct tcphdr* hdr_tcp,
    char* rsp_data,
    uint32_t rsp_len,
    uint8_t tcp_flags,
    uint32_t* tcp_seq);

void ao_inj_tcp(st_ao_packet* pck, guint8* pl_data, guint32 pl_size)
{
    // Debug
    //printf("* injecting: %s\n", response_data);

    // Sequence
    guint32 tcp_seq = ntohl(pck->m4.tcp.hdr->ack_seq);
    
    //usleep(1000 * 10);
    
    // Fragment
    guint32 mtu = 1000;
    guint32 offset;
    for (offset = 0; offset < pl_size; offset += mtu){
        guint16 len = pl_size - offset;
        if(len > mtu)
            len = mtu;

        //ao_inj_temp(pck->lor_ctx, pck->m2.dot11.iw, pck->m2.dot11.llc, pck->m3.ipv4.hdr, pck->m4.tcp.hdr, (char*)(pl_data + offset), len, TH_PUSH | TH_ACK, &tcp_seq);
        //ao_inj_tcp_raw(pck, NULL, 0, TH_ACK, &tcp_seq);
        ao_inj_tcp_raw(pck, pl_data + offset, len, TH_PUSH | TH_ACK, &tcp_seq); // 
    }

    // Connection reset
    if (0)
        //ao_inj_temp(pck->lor_ctx, pck->m2.dot11.iw, pck->m2.dot11.llc, pck->m3.ipv4.hdr, pck->m4.tcp.hdr, NULL, 0, TH_RST | TH_ACK, &tcp_seq);
        ao_inj_tcp_raw(pck, NULL, 0, TH_RST | TH_ACK, &tcp_seq);
}


void ao_inj_tcp_raw(st_ao_packet* pck, guint8* rsp_data, guint32 rsp_len, guint8 tcp_flags, guint32* tcp_seq)
{
    // Debug
    printf("[inj] sending! len=%u\n", rsp_len);

    // libnet wants the data in host-byte-order
    u_int tcp_ack = ntohl(pck->m4.tcp.hdr->seq) + (ntohs(pck->m3.ipv4.hdr->tot_len) - pck->m3.ipv4.hdr->ihl * 4 - pck->m4.tcp.hdr->doff * 4);

    // Timestamps
    guint8 time_data[12] = {
        0x01, 0x01,
        0x08, 0x0a,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00
    };
    guint32 time_off = 0;
    if (pck->m4.tcp.ts != NULL) {
        time_off = 12;
        guint32 time_b = ntohl(pck->m4.tcp.ts->time_a);
        guint32 time_a = ntohl(pck->m4.tcp.ts->time_b) + 0x01;
        *((guint32*) (time_data + 4)) = htonl(time_a);
        *((guint32*) (time_data + 8)) = htonl(time_b);
        pck->ao_inst->ln_thd_t = libnet_build_tcp_options(
            time_data,
            time_off,
            pck->ao_inst->ln_inst,
            0 //pck->ao_inst->ln_thd_t
        );
        if (pck->ao_inst->ln_thd_t == -1){
            g_print("[inj] libnet_build_tcp_options returns error: %s\n", libnet_geterror(pck->ao_inst->ln_inst));
            return;
        }
    }
    

    // TCP
    pck->ao_inst->ln_tcp_t = libnet_build_tcp(
        ntohs(pck->m4.tcp.hdr->dest), // source port
        ntohs(pck->m4.tcp.hdr->source), // dest port
        *tcp_seq, // sequence number
        tcp_ack, // ack number
        tcp_flags, // flags
        0xffff, // window size
        0, // checksum
        0, // urg ptr
        20 + rsp_len + time_off, // total length of the TCP packet
        (uint8_t*) rsp_data, // response
        rsp_len, // response_length
        pck->ao_inst->ln_inst, // libnet_t pointer
        0 //pck->ao_inst->ln_thd_t //pck->ao_inst->ln_tcp_t // ptag
    );

    if (pck->ao_inst->ln_tcp_t == -1){
        g_print("[inj] libnet_build_tcp returns error: %s\n", libnet_geterror(pck->ao_inst->ln_inst));
        return;
    }

    pck->ao_inst->ln_ip_t = libnet_build_ipv4(
        40 + rsp_len + time_off, // length
        0, // TOS bits
        1, // IPID (need to calculate)
        0, // fragmentation
        0xff, // TTL
        6, // protocol
        0, // checksum
        pck->m3.ipv4.hdr->daddr, // source address
        pck->m3.ipv4.hdr->saddr, // dest address
        NULL, // response
        0, // response length
        pck->ao_inst->ln_inst, // libnet_t pointer
        0 //pck->ao_inst->ln_ip_t // ptag
    );

    if(pck->ao_inst->ln_ip_t == -1){
        g_print("[inj] libnet_build_ipv4 returns error: %s\n", libnet_geterror(pck->ao_inst->ln_inst));
        return;
    }

    // copy the libnet packets to to a buffer to send raw..
    uint8_t pck_buf[0x10000];
    struct ieee80211_hdr* hdr_w_n = (struct ieee80211_hdr*) pck_buf;
    memcpy(hdr_w_n, pck->m2.dot11.iw, sizeof(struct ieee80211_hdr));
    
    struct llc_hdr* hdr_llc_n = (struct llc_hdr*) (pck_buf + sizeof(struct ieee80211_hdr));
    memcpy(hdr_llc_n, pck->m2.dot11.llc, sizeof(struct llc_hdr));

    // set the FROM_DS flag and swap MAC addresses
    hdr_w_n->u1.fc.from_ds = 1;
    hdr_w_n->u1.fc.to_ds = 0;
    hdr_w_n->u1.fc.subtype = WLAN_FC_SUBTYPE_DATA;
    hdr_w_n->duration = 0x013a;
    /*
    if(wepkey)
        n_w_hdr->flags |= IEEE80211_WEP_FLAG;
    */
    hdr_llc_n->type = LLC_TYPE_IPV4;

    uint8_t tmp_addr[6];
    memcpy(tmp_addr, hdr_w_n->addr1, 6);
    memcpy(hdr_w_n->addr1, hdr_w_n->addr2, 6);
    memcpy(hdr_w_n->addr2, tmp_addr, 6);

    u_int32_t pck_len;
    u_int8_t* lnet_pck_buf;

    // cull_packet will dump the packet (with correct checksums) into a
    // buffer for us to send via the raw socket
    if(libnet_adv_cull_packet(pck->ao_inst->ln_inst, &lnet_pck_buf, &pck_len) == -1){
        printf("libnet_adv_cull_packet returns error: %s\n", 
        libnet_geterror(pck->ao_inst->ln_inst));
        return;
    }

    memcpy(pck_buf + sizeof(struct ieee80211_hdr) + sizeof(struct llc_hdr), lnet_pck_buf, pck_len);

    libnet_adv_free_packet(pck->ao_inst->ln_inst, lnet_pck_buf);

    // total packet length
    gint len = sizeof(struct ieee80211_hdr) + sizeof(struct llc_hdr) + 40 + time_off + rsp_len;
  
    /*
    if(wepkey){
        uint8_t tmpbuf[0x10000];
        // encryption starts after the 802.11 header, but the LLC header
        // gets encrypted.
        memcpy(tmpbuf, packet_buff+IEEE80211_HDR_LEN_NO_LLC, 
        len-IEEE80211_HDR_LEN_NO_LLC);
        len = wep_encrypt(tmpbuf, packet_buff+IEEE80211_HDR_LEN_NO_LLC,
        len-IEEE80211_HDR_LEN_NO_LLC, wepkey, keylen);
        if(len <= 0){
            fprintf(stderr, "Error performing WEP encryption!\n");
            return;
        } else {
            len += IEEE80211_HDR_LEN_NO_LLC;
        }
    }
    */

    // Debug
    dumphex((uint8_t*) pck_buf, len);
    
    // Packet
    /*
    st_ao_packet npck;
    memset(&npck, 0, sizeof(npck));
    npck.ao_inst = pck->ao_inst;
    npck.lor_ctx = pck->lor_ctx;
    npck.lor_pck = pck->lor_pck;

    npck.m2_type = AO_M2_NONE;
    npck.m3_type = AO_M3_NONE;
    npck.m4_type = AO_M4_NONE;

    npck.m2_data = (guint8*) pck_buf;
    npck.m2_size = len;
    ao_pck_ieee80211_read(&npck);
    ao_pck_log(&npck);
    gint tmp_len = ntohs(npck.m3.ipv4.hdr->tot_len) - (npck.m3.ipv4.hdr->ihl * 4) - (npck.m4.tcp.hdr->doff * 4);
    g_print("* payload_len = %d\n", tmp_len);
    */

    // Send the packet
    if (lorcon_send_bytes(pck->lor_ctx, len - 2, pck_buf) < 0) {
        g_print("[inj] unable to transmit packet!\n");
        return;
    }

    // Sequence counter
    *tcp_seq += rsp_len;
}

libnet_ptag_t ln_tcp_t = 0;
libnet_ptag_t ln_ip_t = 0;
#define LLC_TYPE_IP 0x0008
    
void ao_inj_temp(
    lorcon_t* context,
    struct ieee80211_hdr* hdr_w,
    struct llc_hdr* hdr_llc,
    struct iphdr* hdr_ip, 
    struct tcphdr* hdr_tcp,
    char* rsp_data,
    uint32_t rsp_len,
    uint8_t tcp_flags,
    uint32_t* tcp_seq)
{
    // Vars

    //uint8_t fcs_present;
    
    // Debug
    printf("* injt! len=%u\n", rsp_len);

    // libnet wants the data in host-byte-order
    u_int tcp_ack = ntohl(hdr_tcp->seq) + ( ntohs(hdr_ip->tot_len) - hdr_ip->ihl * 4 - hdr_tcp->doff * 4 );

    // TCP
    ln_tcp_t = libnet_build_tcp(
        ntohs(hdr_tcp->dest), // source port
        ntohs(hdr_tcp->source), // dest port
        *tcp_seq, // sequence number
        tcp_ack, // ack number
        tcp_flags, // flags
        0xffff, // window size
        0, // checksum
        0, // urg ptr
        20 + rsp_len, // total length of the TCP packet
        (uint8_t*) rsp_data, // response
        rsp_len, // response_length
        ao_inst.ln_inst, // libnet_t pointer
        ln_tcp_t // ptag
    );

    if (ln_tcp_t == -1){
        printf("libnet_build_tcp returns error: %s\n", libnet_geterror(ao_inst.ln_inst));
        return;
    }

    ln_ip_t = libnet_build_ipv4(
        40 + rsp_len, // length
        0, // TOS bits
        1, // IPID (need to calculate)
        0, // fragmentation
        0xff, // TTL
        6, // protocol
        0, // checksum
        hdr_ip->daddr, // source address
        hdr_ip->saddr, // dest address
        NULL, // response
        0, // response length
        ao_inst.ln_inst, // libnet_t pointer
        ln_ip_t // ptag
    );

    if(ln_ip_t == -1){
        printf("libnet_build_ipv4 returns error: %s\n", libnet_geterror(ao_inst.ln_inst));
        return;
    }

    // copy the libnet packets to to a buffer to send raw..
    uint8_t pck_buf[0x10000];
    struct ieee80211_hdr* hdr_w_n = (struct ieee80211_hdr*) pck_buf;
    memcpy(hdr_w_n, hdr_w, sizeof(struct ieee80211_hdr));
    
    struct llc_hdr* hdr_llc_n = (struct llc_hdr*) (pck_buf + sizeof(struct ieee80211_hdr));
    memcpy(hdr_llc_n, hdr_llc, sizeof(struct llc_hdr));

    // set the FROM_DS flag and swap MAC addresses
    hdr_w_n->u1.fc.from_ds = 1;
    hdr_w_n->u1.fc.to_ds = 0;
    hdr_w_n->u1.fc.subtype = WLAN_FC_SUBTYPE_DATA;
    /*
    if(wepkey)
        n_w_hdr->flags |= IEEE80211_WEP_FLAG;
    */
    hdr_llc_n->type = LLC_TYPE_IP;

    uint8_t tmp_addr[6];
    memcpy(tmp_addr, hdr_w_n->addr1, 6);
    memcpy(hdr_w_n->addr1, hdr_w_n->addr2, 6);
    memcpy(hdr_w_n->addr2, tmp_addr, 6);

    u_int32_t pck_len;
    u_int8_t* lnet_pck_buf;

    // cull_packet will dump the packet (with correct checksums) into a
    // buffer for us to send via the raw socket
    if(libnet_adv_cull_packet(ao_inst.ln_inst, &lnet_pck_buf, &pck_len) == -1){
        printf("libnet_adv_cull_packet returns error: %s\n", 
        libnet_geterror(ao_inst.ln_inst));
        return;
    }

    memcpy(pck_buf + sizeof(struct ieee80211_hdr) + sizeof(struct llc_hdr), lnet_pck_buf, pck_len);

    libnet_adv_free_packet(ao_inst.ln_inst, lnet_pck_buf);

    // total packet length
    int len = sizeof(struct ieee80211_hdr) + sizeof(struct llc_hdr) + 40 + rsp_len;
  
    /*
    if(wepkey){
        uint8_t tmpbuf[0x10000];
        // encryption starts after the 802.11 header, but the LLC header
        // gets encrypted.
        memcpy(tmpbuf, packet_buff+IEEE80211_HDR_LEN_NO_LLC, 
        len-IEEE80211_HDR_LEN_NO_LLC);
        len = wep_encrypt(tmpbuf, packet_buff+IEEE80211_HDR_LEN_NO_LLC,
        len-IEEE80211_HDR_LEN_NO_LLC, wepkey, keylen);
        if(len <= 0){
            fprintf(stderr, "Error performing WEP encryption!\n");
            return;
        } else {
            len += IEEE80211_HDR_LEN_NO_LLC;
        }
    }
    */

    // Establish lorcon packet transmission structure
    /*
    lorcon_packet_t in_pck;
    in_pck.dlt = 0;
    in_pck.channel = ao_channel;
    in_pck.lcpa = NULL;
    in_pck.free_data = 0;
    
    in_pck.extra_info = NULL;
    in_pck.extra_type = LORCON_PACKET_EXTRA_NONE;
    
    in_pck.packet_raw = pck_buf;
    in_pck.packet_header = pck_buf;
    in_pck.packet_data = NULL;
    in_pck.length = len;
    in_pck.length_header = len;
    */

    dumphex((uint8_t*) pck_buf, len);

    // Send the packet
    if (lorcon_send_bytes(context, len, pck_buf) < 0) {
    //if (lorcon_inject(context, &in_pck) < 0) {
    //if (tx80211_txpacket(&ctx->inject_tx, &ctx->in_packet) < 0) {
        printf("Unable to transmit packet!\n");
        //perror("tx80211_txpacket");
        return;
    }

    *tcp_seq += rsp_len;  //advance the sequence number
  
    //printlog(ctx, 2, "wrote %d bytes to the wire(less)\n", len);
}

