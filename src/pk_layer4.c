/*
 * Airown - layer 4 analysis
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
#include "pk_layer4.h"

// Functions
void pck_tcp_read(st_ao_packet* pck)
{
    if (pck->m4_size >= sizeof(struct tcphdr)) {
        // Header
        pck->m4.tcp.hdr = (struct tcphdr*) pck->m4_data;
        
        // Lengths and offsets
        guint16 tcp_len = 0;
        if (pck->m3_type == AO_M3_IPV4) {
            tcp_len = ntohs(pck->m3.ipv4.hdr->tot_len) - (pck->m3.ipv4.hdr->ihl * 4) - (pck->m4.tcp.hdr->doff * 4);
        } else if (pck->m3_type == AO_M3_IPV6) {
            tcp_len = ntohs(pck->m3.ipv4.hdr->tot_len) - sizeof(struct libnet_ipv6_hdr) - (pck->m4.tcp.hdr->doff * 4);
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

void pck_tcp_free(st_ao_packet* pck)
{

}

void pck_udp_read(st_ao_packet* pck)
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

void pck_udp_free(st_ao_packet* pck)
{

}

