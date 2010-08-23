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
#include "pk_inject_tcp.h"

// Declarations
static void inj_tcp_raw(st_ao_packet* pck, guint8* rsp_data, guint32 rsp_len, guint8 tcp_flags, guint32* tcp_seq);

/**
 * \brief Inject TCP packet
 * \param pck Received TCP packet that will be replied
 * \param pl_data Payload data
 * |param pl_size Payload size
 */
void inj_tcp(st_ao_packet* pck, guint8* pl_data, guint32 pl_size)
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
        inj_tcp_raw(pck, pl_data + offset, len, TH_PUSH | TH_ACK, &tcp_seq); // 
    }

    // Connection reset
    if (0)
        //ao_inj_temp(pck->lor_ctx, pck->m2.dot11.iw, pck->m2.dot11.llc, pck->m3.ipv4.hdr, pck->m4.tcp.hdr, NULL, 0, TH_RST | TH_ACK, &tcp_seq);
        inj_tcp_raw(pck, NULL, 0, TH_RST | TH_ACK, &tcp_seq);
}

static void inj_tcp_raw(st_ao_packet* pck, guint8* rsp_data, guint32 rsp_len, guint8 tcp_flags, guint32* tcp_seq)
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

