/*
 * Airown - TCP
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
#include "pk_packet.h"
#include "st_tcp.h"

// Declarations
static gint stcp_cmp(gconstpointer ptr_a, gconstpointer ptr_b);
static void stcp_syn(st_ao_packet* pck);
static void stcp_fin(st_tcpcon* con);
static void stcp_pck(st_tcpcon* con, st_ao_packet* pck);
//static void stcp_pl(st_tcp_con* con);

// Data
GList* ctcp_con = NULL;
guint32 ctcp_id = 0;

// Functions
void st_tcp_packet(st_ao_packet* pck)
{
    // Check if TCP/IP
    if (pck->m4_type != AO_M4_TCP)
        return;
    if ((pck->m3_type != AO_M3_IPV4) && (pck->m3_type != AO_M3_IPV6))
        return;
    
    // Accept only non-null ports
    if ((ntohs(pck->m4.tcp.hdr->th_sport) == 0) || (ntohs(pck->m4.tcp.hdr->th_dport) == 0))
        return;

    // Find connection
    GList* clist = g_list_find_custom(ctcp_con, pck, stcp_cmp);
    if (clist != NULL) {
        // Found
        stcp_pck((st_tcpcon*) clist->data, pck);
    } else {
        // Not found
        stcp_syn(pck);
    }
}

static gint stcp_cmp(gconstpointer ptr_a, gconstpointer ptr_b)
{
    const st_tcpcon* con = (const st_tcpcon*) ptr_a;
    const st_ao_packet* pck = (const st_ao_packet*) ptr_b;
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
        
        if (cmp_ipv4((struct in_addr*) &(con->ip4_a), (struct in_addr*) &(pck->m3.ipv4.hdr->ip_src)) == TRUE) {
            if (cmp_ipv4((struct in_addr*) &(con->ip4_b), (struct in_addr*) &(pck->m3.ipv4.hdr->ip_dst)) == FALSE)
                return 1;
            
            // a = src, b = dst
            is_rev = FALSE;
        
        } else if (cmp_ipv4((struct in_addr*) &(con->ip4_b), (struct in_addr*) &(pck->m3.ipv4.hdr->ip_src)) == TRUE) {
            if (cmp_ipv4((struct in_addr*) &(con->ip4_a), (struct in_addr*) &(pck->m3.ipv4.hdr->ip_dst)) == FALSE)
                return 1;
                
            // a = dst, b = src
            is_rev = TRUE;
        
        } else {
            return 1;
        }
        
    } else if (pck->m3_type == AO_M3_IPV6) {
    
        if (cmp_ipv6((struct libnet_in6_addr*) &(con->ip6_a), (struct libnet_in6_addr*) &(pck->m3.ipv6.hdr->ip_src)) == TRUE) {
            if (cmp_ipv6((struct libnet_in6_addr*) &(con->ip6_b), (struct libnet_in6_addr*) &(pck->m3.ipv6.hdr->ip_dst)) == FALSE)
                return 1;
            
            // a = src, b = dst
            is_rev = FALSE;
        
        } else if (cmp_ipv6((struct libnet_in6_addr*) &(con->ip6_b), (struct libnet_in6_addr*) &(pck->m3.ipv6.hdr->ip_src)) == TRUE) {
            if (cmp_ipv6((struct libnet_in6_addr*) &(con->ip6_a), (struct libnet_in6_addr*) &(pck->m3.ipv6.hdr->ip_dst)) == FALSE)
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
        if ((ntohs(pck->m4.tcp.hdr->th_sport) != con->port_a) ||
            (ntohs(pck->m4.tcp.hdr->th_dport) != con->port_b))
            return 1;
    } else {
        if ((ntohs(pck->m4.tcp.hdr->th_sport) != con->port_b) ||
            (ntohs(pck->m4.tcp.hdr->th_dport) != con->port_a))
            return 1;
    }
    
    // Success
    return 0;
}

static void stcp_syn(st_ao_packet* pck)
{
    // Skip FIN and RST packets
    guint8 flags = pck->m4.tcp.hdr->th_flags;
    if ((flags & TH_FIN) || (flags & TH_RST))
        return;

    // Alloc
    st_tcpcon* con = g_new(st_tcpcon, 1);
    memset(con, 0, sizeof(st_tcpcon));
    
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
    if ((flags & TH_SYN) && !(flags & TH_ACK)) {
        // SYN
        con->con_syn = 1;
        is_rev = FALSE;
    } else if ((flags & TH_SYN) && (flags & TH_ACK)) {
        // SYN+ACK
        con->con_syn = 2;
        is_rev = TRUE;
    } else {
        // Guess using NAT IP and mask
        con->con_syn = 3;
        gboolean nat_ok = FALSE;
        if (con->proto == AO_M3_IPV4 && pck->ao_inst->cmd_nat4_ip && pck->ao_inst->cmd_nat4_mask) {
        
            struct in_addr nat_ip;
            struct in_addr nat_mask;
            if ((inet_pton(AF_INET, pck->ao_inst->cmd_nat4_ip, &nat_ip) == 1) &&
                (inet_pton(AF_INET, pck->ao_inst->cmd_nat4_mask, &nat_mask) == 1)) {
                gboolean isrc = cmp_ipv4_mask((struct in_addr*) &nat_ip, (struct in_addr*) &(pck->m3.ipv4.hdr->ip_src), (struct in_addr*) &nat_mask);
                gboolean idst = cmp_ipv4_mask((struct in_addr*) &nat_ip, (struct in_addr*) &(pck->m3.ipv4.hdr->ip_dst), (struct in_addr*) &nat_mask);
                
                if (isrc && !idst) {
                    is_rev = FALSE;
                    nat_ok = TRUE;
                } else if (!isrc && idst) {
                    is_rev = TRUE;
                    nat_ok = TRUE;
                }
            }
            
        } else if (con->proto == AO_M3_IPV6 && pck->ao_inst->cmd_nat6_ip && pck->ao_inst->cmd_nat6_mask) {
        
            struct libnet_in6_addr nat_ip;
            struct libnet_in6_addr nat_mask;
            if ((inet_pton(AF_INET6, pck->ao_inst->cmd_nat6_ip, &nat_ip) == 1) &&
                (inet_pton(AF_INET6, pck->ao_inst->cmd_nat6_mask, &nat_mask) == 1)) {
                gboolean isrc = cmp_ipv6_mask((struct libnet_in6_addr*) &nat_ip, (struct libnet_in6_addr*) &(pck->m3.ipv6.hdr->ip_src), (struct libnet_in6_addr*) &nat_mask);
                gboolean idst = cmp_ipv6_mask((struct libnet_in6_addr*) &nat_ip, (struct libnet_in6_addr*) &(pck->m3.ipv6.hdr->ip_dst), (struct libnet_in6_addr*) &nat_mask);
                
                if (isrc && !idst) {
                    is_rev = FALSE;
                    nat_ok = TRUE;
                } else if (!isrc && idst) {
                    is_rev = TRUE;
                    nat_ok = TRUE;
                }
            }
        
        }
        
        // Guess using lower port number as b and higher as a
        // This will not work with P2P and similar protocols, but should be a
        // pretty good guess with traditional services like HTTP.
        if (nat_ok == FALSE) {
            if (ntohs(pck->m4.tcp.hdr->th_sport) > ntohs(pck->m4.tcp.hdr->th_dport)) {
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
            cpy_ipv4(&(con->ip4_a), (struct in_addr*) &(pck->m3.ipv4.hdr->ip_src));
            cpy_ipv4(&(con->ip4_b), (struct in_addr*) &(pck->m3.ipv4.hdr->ip_dst));
        } else if (con->proto == AO_M3_IPV6) {
            cpy_ipv6(&(con->ip6_a), (struct libnet_in6_addr*) &(pck->m3.ipv6.hdr->ip_src));
            cpy_ipv6(&(con->ip6_b), (struct libnet_in6_addr*) &(pck->m3.ipv6.hdr->ip_dst));
        }
        
        // Ports
        con->port_a = ntohs(pck->m4.tcp.hdr->th_sport);
        con->port_b = ntohs(pck->m4.tcp.hdr->th_dport);
        
        // Sequence
        con->seq_a = ntohl(pck->m4.tcp.hdr->th_seq);
        con->seq_b = 0;
        
    } else {
    
        // Addresses
        if (con->proto == AO_M3_IPV4) {
            cpy_ipv4(&(con->ip4_b), (struct in_addr*) &(pck->m3.ipv4.hdr->ip_src));
            cpy_ipv4(&(con->ip4_a), (struct in_addr*) &(pck->m3.ipv4.hdr->ip_dst));
        } else if (con->proto == AO_M3_IPV6) {
            cpy_ipv6(&(con->ip6_b), (struct libnet_in6_addr*) &(pck->m3.ipv6.hdr->ip_src));
            cpy_ipv6(&(con->ip6_a), (struct libnet_in6_addr*) &(pck->m3.ipv6.hdr->ip_dst));
        }
        
        // Ports
        con->port_b = ntohs(pck->m4.tcp.hdr->th_sport);
        con->port_a = ntohs(pck->m4.tcp.hdr->th_dport);
        
        // Sequence
        con->seq_a = ntohl(pck->m4.tcp.hdr->th_ack);
        con->seq_b = ntohl(pck->m4.tcp.hdr->th_seq);
        
    }
    
    // Packets
    con->pck_queue = g_queue_new();
    con->pck_num = 1;
    con->pck_total_size = 0;
    con->pck_buf_size = 0;
    
    // Log
    con->log_file = NULL;
    if (ao_inst.cmd_tcp_raw) {
        gchar* fn_file = NULL;
        if (con->proto == AO_M3_IPV4) {
            guint32 ip_a = con->ip4_a.s_addr;
            guint32 ip_b = con->ip4_b.s_addr;
            fn_file = g_strdup_printf("0x%04x_a-%03u.%03u.%03u.%03u-%05u_b-%03u.%03u.%03u.%03u-%05u.log",
                ctcp_id,
                (ip_a) & 0xff, (ip_a >> 8) & 0xff, (ip_a >> 16) & 0xff, (ip_a >> 24) & 0xff,
                con->port_a,
                (ip_b) & 0xff, (ip_b >> 8) & 0xff, (ip_b >> 16) & 0xff, (ip_b >> 24) & 0xff,
                con->port_b);
        } else if (con->proto == AO_M3_IPV6) {
            guint32* addr_a = (guint32*) &(con->ip6_a.__u6_addr.__u6_addr32);
            guint32* addr_b = (guint32*) &(con->ip6_b.__u6_addr.__u6_addr32);
            fn_file = g_strdup_printf("0x%04x_a-%08x%08x%08x%08x-%05u_b-%08x%08x%08x%08x-%05u.log",
                ctcp_id,
                addr_a[0], addr_a[1], addr_a[2], addr_a[3],
                con->port_a,
                addr_b[0], addr_b[1], addr_b[2], addr_b[3],
                con->port_b);
        } else {
            fn_file = g_strdup_printf("0x%04x.log", ctcp_id);
        }
        gchar* fn_path = g_strconcat(ao_inst.cmd_tcp_raw, G_DIR_SEPARATOR_S, fn_file, NULL);
        
        con->log_file = fopen(fn_path, "w");
        if (con->log_file) {

            // Headers
            fprintf(con->log_file, "<===> TCP stream log <=========================================================>\n");
            fprintf(con->log_file, "host_a = \n");
            fprintf(con->log_file, "host_b = \n");
        }
        
        g_free(fn_file);
        g_free(fn_path);
    }
    
    // Save
    ctcp_con = g_list_append(ctcp_con, con);
    
    // If have data
    if (pck->pl_size > 0)
        stcp_pck(con, pck);
    
    // Id
    ctcp_id++;
}

static void stcp_fin(st_tcpcon* con)
{
    // Payload
    /*
    if (con->pl_type == AO_PL_HTTP) {
        
    }
    */
    
    // Log
    if (con->log_file) {
        fclose(con->log_file);
    }
    
    // Packets
    st_tcppck* tpck;
    while ((tpck = (st_tcppck*) g_queue_pop_head(con->pck_queue)) != NULL) {
        g_free(tpck->pl_data);
        g_free(tpck);
    }
    
    // Remove from list
    ctcp_con = g_list_remove(ctcp_con, con);
    
    // Free memory
    g_free(con);
}

static void stcp_pck(st_tcpcon* con, st_ao_packet* pck)
{
    // Direction
    gboolean is_rev = FALSE;
    if (pck->m3_type == AO_M3_IPV4) {
        if (cmp_ipv4(&(con->ip4_a), (struct in_addr*) &(pck->m3.ipv4.hdr->ip_src)) == TRUE) {
            is_rev = FALSE;
        } else {
            is_rev = TRUE;
        }
    } else if (pck->m3_type == AO_M3_IPV6) {
        if (cmp_ipv6(&(con->ip6_a), (struct libnet_in6_addr*) &(pck->m3.ipv6.hdr->ip_src)) == TRUE) {
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
    guint8 flags = pck->m4.tcp.hdr->th_flags;
    if ((flags & TH_SYN) && (flags & TH_ACK) && (con->con_syn == 1))
        con->con_syn = 2;
    if ((flags & TH_ACK) && (con->con_syn == 2))
        con->con_syn = 3;
    if (con->pck_num >= 3)
        con->con_syn = 3;
        
    // FIN
    if ((flags & TH_ACK) && (con->con_fin == 1))
        con->con_fin = 2;
    if (flags & TH_FIN)
        con->con_fin = 1;
    
    // RST
    if (flags & TH_RST)
        con->con_rst = 1;

    // Log
    if (con->log_file) {
        // General
        fprintf(con->log_file, "<==============================================================================>\n");
        gchar* timestr = g_time_val_to_iso8601(&(con->time_last));
        fprintf(con->log_file, "[ %s ][ a %s b ][ %s%s%s%s%s%s]\n",
            timestr,
            is_rev ? "<=" : "=>",
            flags & TH_SYN ? "SYN " : "",
            flags & TH_ACK ? "ACK " : "",
            flags & TH_PUSH ? "PSH " : "",
            flags & TH_FIN ? "FIN " : "",
            flags & TH_RST ? "RST " : "",
            flags & TH_URG ? "URG " : ""
        );
        g_free(timestr);
        
        // Payload
        if (pck->pl_size > 0)
            dumphex_file(con->log_file, pck->pl_data, pck->pl_size);
        
        // Ending
        fprintf(con->log_file, "\n");
    }
    
    // Payload recovery
    /*
    if (pck->pl_size > 0) {
        // Copy memory
        st_tcp_pck* tpck = g_new(st_tcp_pck, 1);
        tpck->dir_send = (is_rev ? FALSE : TRUE);
        tpck->pl_size = pck->pl_size;
        tpck->pl_data = g_memdup(pck->pl_data, pck->pl_size);
        g_queue_push_head(con->pck_queue, tpck);
        
        // Size
        con->pck_total_size += pck->pl_size;
        con->pck_buf_size += pck->pl_size;
        
        // Log
        if (con->log_file) {
            fprintf(con->log_file, "pck! size=%u\n", pck->pl_size);
        }
        
        // Process payload
        if (con->con_syn >= 3) {
            stcp_pl(con);
        }
    }
    */
    
    // Ending connection
    if (con->con_fin == 2 || con->con_rst == 1) {
        stcp_fin(con);
    }
}

/*
void ctx_tcp_pl(st_tcp_con* con)
{
    // Identification
    if (con->pl_type == AO_PL_NONE) {
        st_tcp_pck* tpck = g_queue_peek_tail(con->pck_queue);
        if (tpck != NULL) {
            // HTTP GET
            gchar* hstr_http_get = "GET ";
            if (tpck->pl_size >= strlen(hstr_http_get)) {
            
            }
        }
    }

    // Protocols
    if (con->pl_type == AO_PL_HTTP) {
    
    }
}
*/

