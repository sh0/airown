/*
 * Airown - content
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

// Data
GList* ctcp_con = NULL;

// Functions
gint ctx_tcp_cmp(const st_tcp_con* con, const st_ao_packet* pck)
{
    // Check if open
    if (con->con_fin)
        return 1;
    
    // Protocol types
    if (con->proto != pck->m3_type)
        return 1;
    if (pck->m4_type != AO_M4_TCP)
        return 1;
    
    // IP version
    gboolean is_rev = FALSE;
    if (pck->m3_type == AO_M3_IPV4) {
        
        if (cmp_ipv4(&(con->ip4_a), &(pck->m3.ipv4.hdr->saddr)) == TRUE) {
            if (cmp_ipv4(&(con->ip4_b), &(pck->m3.ipv4.hdr->daddr)) == FALSE)
                return 1;
            
            // a = src, b = dst
            is_rev = FALSE;
        
        } else if (cmp_ipv4(&(con->ip4_b), &(pck->m3.ipv4.hdr->saddr)) == TRUE) {
            if (cmp_ipv4(&(con->ip4_a), &(pck->m3.ipv4.hdr->daddr)) == FALSE)
                return 1;
                
            // a = dst, b = src
            is_rev = TRUE;
        
        } else {
            return 1;
        }
        
    } else if (pck->m3_type == AO_M3_IPV6) {
    
        if (cmp_ipv6(&(con->ip6_a), &(pck->m3.ipv6.hdr->saddr)) == TRUE) {
            if (cmp_ipv6(&(con->ip6_b), &(pck->m3.ipv6.hdr->daddr)) == FALSE)
                return 1;
            
            // a = src, b = dst
            is_rev = FALSE;
        
        } else if (cmp_ipv6(&(con->ip6_b), &(pck->m3.ipv6.hdr->saddr)) == TRUE) {
            if (cmp_ipv6(&(con->ip6_a), &(pck->m3.ipv6.hdr->daddr)) == FALSE)
                return 1;
                
            // a = dst, b = src
            is_rev = TRUE;
        
        } else {
            return 1;
        }
    
    } else {
        return 1;
    }
    
    // TCP
    if (is_rev == FALSE) {
        if ((ntohs(pck->m4.tcp.hdr->source) != con->port_a) ||
            (ntohs(pck->m4.tcp.hdr->dest) != con->port_b))
            return 1;
    } else {
        if ((ntohs(pck->m4.tcp.hdr->source) != con->port_b) ||
            (ntohs(pck->m4.tcp.hdr->dest) != con->port_a))
            return 1;
    }
    
    // Success
    return 0;
}

void ctx_tcp_pl(st_tcp_con* con, st_ao_packet* pck)
{

}

void ctx_tcp_pck(st_tcp_con* con, st_ao_packet* pck)
{
    // Direction
    gboolean is_rev = FALSE;
    if (pck->m3_type == AO_M3_IPV4) {
        if (cmp_ipv4(&(con->ip4_a), &(pck->m3.ipv4.hdr->saddr)) == TRUE) {
            is_rev = FALSE;
        } else {
            is_rev = TRUE;
        }
    } else if (pck->m3_type == AO_M3_IPV6) {
        if (cmp_ipv6(&(con->ip6_a), &(pck->m3.ipv6.hdr->saddr)) == TRUE) {
            is_rev = FALSE;
        } else {
            is_rev = TRUE;
        }
    } else {
        return;
    }
    
    // Count
    con->pck_num++;
    
    // Times
    g_get_current_time(&(con->time_last));
    
    // SYN
    if (pck->m4.tcp.hdr->syn && pck->m4.tcp.hdr->ack && con->con_syn == 1)
        con->con_syn = 2;
    if (pck->m4.tcp.hdr->ack && con->con_syn == 2)
        con->con_syn = 3;
    if (con->pck_num >= 3)
        con->con_syn = 3;
        
    // FIN
    if (pck->m4.tcp.hdr->ack && con->con_fin == 1)
        con->con_fin = 2;
    if (pck->m4.tcp.hdr->fin)
        con->con_fin = 1;
    
    // RST
    if (pck->m4.tcp.hdr->rst)
        con->con_rst = 1;
    
    // Payload recovery
    if (pck->pl_size > 0) {
        // Copy memory
        st_tcp_pck* tpck = g_new(st_tcp_pck, 1);
        tpck->dir_send = (is_rev ? FALSE : TRUE);
        tpck->pl_size = pck->pl_size;
        tpck->pl_data = g_memdup(pck->pl_data, pck->pl_size);
        pck->pck_queue = g_queue_push_head(pck->pck_queue, tpck);
        
        // Log
    }
    
    // Process payload
    if (con->con_syn >= 3) {
        ctx_tcp_pl(con, pck);
    }
}

void ctx_tcp_new(st_ao_packet* pck)
{
    // Skip FIN and RST packets
    if (pck->m4.tcp.hdr->fin || pck->m4.tcp.hdr->rst)
        return;

    // Alloc
    st_tcp_con* con = g_new(st_tcp_con, 1);
    memset(con, 0, sizeof(st_tcp_con));
    
    // Protocol
    con->proto = pck->m3_type;
    
    // Set flags
    con->con_syn = 0;
    con->con_fin = 0;
    con->con_rst = 0;
    
    // Times
    g_get_current_time(&(con->time_first));
    g_get_current_time(&(con->time_last));
    
    // Packet direction and syn level
    gboolean is_rev = FALSE;
    if (pck->m4.tcp.hdr->syn && !pck->m4.tcp.hdr->ack) {
        // SYN
        con->con_syn = 1;
        is_rev = FALSE;
    } else if (pck->m4.tcp.hdr->syn && pck->m4.tcp.hdr->ack) {
        // SYN+ACK
        con->con_syn = 2;
        is_rev = TRUE;
    } else {
        // Guess using NAT ip and mask
        con->con_syn = 3;
        gboolean nat_ok = FALSE;
        if (pck->ao_inst->nat_ip && pck->ao_inst->nat_mask) {
            if (con->proto == AO_M3_IPV4) {
            
                in_addr nat_ip;
                in_addr nat_mask;
                if ((inet_pton(AF_INET, pck->ao_inst->nat4_ip, &nat_ip) == 1) &&
                    (inet_pton(AF_INET, pck->ao_inst->nat4_mask, &nat_mask) == 1)) {
                    gboolean isrc = cmp_ipv4_mask(&nat_ip, &(pck->m3.ipv4.hdr->saddr), &nat_mask);
                    gboolean idst = cmp_ipv4_mask(&nat_ip, &(pck->m3.ipv4.hdr->daddr), &nat_mask);
                    
                    if (isrc && !idst) {
                        is_rev = FALSE;
                        nat_ok = TRUE;
                    } else if (!isrc && idst) {
                        is_rev = TRUE;
                        nat_ok = TRUE;
                    }
                }
                
            } else if (con->proto == AO_M3_IPV6) {
            
                in6_addr nat_ip;
                in6_addr nat_mask;
                if ((inet_pton(AF_INET6, pck->ao_inst->nat6_ip, &nat_ip) == 1) &&
                    (inet_pton(AF_INET6, pck->ao_inst->nat6_mask, &nat_mask) == 1)) {
                    gboolean isrc = cmp_ipv6_mask(&nat_ip, &(pck->m3.ipv6.hdr->saddr), &nat_mask);
                    gboolean idst = cmp_ipv6_mask(&nat_ip, &(pck->m3.ipv6.hdr->daddr), &nat_mask);
                    
                    if (isrc && !idst) {
                        is_rev = FALSE;
                        nat_ok = TRUE;
                    } else if (!isrc && idst) {
                        is_rev = TRUE;
                        nat_ok = TRUE;
                    }
                }
            
            }
        }
        
        // Guess using lower port number as b and higher as a
        // This will not work with P2P and similar protocols, but should be a
        // pretty good guess with traditional services.
        if (nat_ok == FALSE) {
            if (ntohs(pck->m4.tcp.hdr->source) > ntohs(pck->m4.tcp.hdr->dest)) {
                is_rev = FALSE;
            } else {
                is_rev = TRUE;
            }
        }
    }
    
    // Set data
    if (is_rev == FALSE) {
    
        // Addresses
        if (con->proto == AO_M3_IPV4) {
            cpy_ipv4(&(con->ip4_a), &(pck->m3.ipv4.hdr->saddr));
            cpy_ipv4(&(con->ip4_b), &(pck->m3.ipv4.hdr->daddr));
        } else if (con->proto == AO_M3_IPV6) {
            cpy_ipv6(&(con->ip6_a), &(pck->m3.ipv6.hdr->saddr));
            cpy_ipv6(&(con->ip6_b), &(pck->m3.ipv6.hdr->daddr));
        }
        
        // Ports
        con->port_a = ntohs(pck->m4.tcp.hdr->source);
        con->port_b = ntohs(pck->m4.tcp.hdr->dest);
        
        // Sequence
        con->seq_a = ntohl(pck->m4.tcp.hdr->seq);
        con->seq_b = 0;
        
    } else {
    
        // Addresses
        if (con->proto == AO_M3_IPV4) {
            cpy_ipv4(&(con->ip4_b), &(pck->m3.ipv4.hdr->saddr));
            cpy_ipv4(&(con->ip4_a), &(pck->m3.ipv4.hdr->daddr));
        } else if (con->proto == AO_M3_IPV6) {
            cpy_ipv6(&(con->ip6_b), &(pck->m3.ipv6.hdr->saddr));
            cpy_ipv6(&(con->ip6_a), &(pck->m3.ipv6.hdr->daddr));
        }
        
        // Ports
        con->port_b = ntohs(pck->m4.tcp.hdr->source);
        con->port_a = ntohs(pck->m4.tcp.hdr->dest);
        
        // Sequence
        con->seq_a = ntohl(pck->m4.tcp.hdr->ack_seq);
        con->seq_b = ntohl(pck->m4.tcp.hdr->seq);
        
    }
    
    // Packets
    con->pck_queue = g_queue_new();
    con->pck_num = 1;
    con->pck_size = 0;
    
    // Save
    ctcp_con = g_list_append(ctcp_con, con);
    
    // If have data
    if (pck->pl_size > 0)
        ctx_tcp_pck(con, pck);
}

void ctx_tcp_proc(st_ao_packet* pck)
{
    // Check if TCP/IP
    if (pck->m4_type != AO_M4_TCP)
        return;
    if ((pck->m3_type != AO_M3_IPV4) && (pck->m3_type != AO_M4_IPV6))
        return;
    
    // Accept only non-null ports
    if ((ntohs(pck->m4.tcp.hdr->source) == 0) || (ntohs(pck->m4.tcp.hdr->dest) == 0))
        return;

    // Find connection
    GList* clist = g_list_find_custom(ctcp_con, pck, ctx_tcp_cmp);
    if (clist != NULL) {
        // Found
        ctx_tcp_pck((st_tcp_con*) clist->data, pck);
    } else {
        // Not found
        ctc_tcp_new(pck);
    }
}

void ctx_tcp_audit()
{

}

