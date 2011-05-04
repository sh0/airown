/*
 * Airown - layer 2 analysis
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
#include "pk_layer2.h"
#include "pk_layer3.h"

// Dot11 info field structure
typedef struct {
    guint8 id;
    guint8 length;
    guint8* data;
} st_wlan_field;

// Dot11 info field types
typedef enum {
    WLAN_INFO_SSID = 0,
    WLAN_INFO_RATES,
    WLAN_INFO_FH_PARAM,
    WLAN_INFO_DS_PARAM,
    WLAN_INFO_CF_PARAM,
    WLAN_INFO_TIM,
    WLAN_INFO_IBSS_PARAM,
    WLAN_INFO_COUNTRY,
    WLAN_INFO_HOP_PARAM,
    WLAN_INFO_HOP_TABLE,
    WLAN_INFO_REQUEST,
    WLAN_INFO_BSS_LOAD,
    WLAN_INFO_EDCA_PARAM,
    WLAN_INFO_TSPEC,
    WLAN_INFO_TCLAS,
    WLAN_INFO_SCHEDULE,
    WLAN_INFO_CHALLENGE,
    // RESERVED = 17 - 31
    WLAN_INFO_POWER_CONST = 32,
    WLAN_INFO_POWER_CAPS,
    WLAN_INFO_TPC_REQUEST,
    WLAN_INFO_TPC_REPORT,
    WLAN_INFO_SUPPORT_CHAN,
    WLAN_INFO_CHAN_SWITCH,
    WLAN_INFO_MEAS_REQUEST,
    WLAN_INFO_MEAS_REPORT,
    WLAN_INFO_QUIET,
    WLAN_INFO_IBSS_DFS,
    WLAN_INFO_ERP_INFO,
    WLAN_INFO_TS_DELAY,
    WLAN_INFO_TCLAS_PROC,
    // RESERVED = 45
    WLAN_INFO_QOS_CAPS = 46,
    // RESERVED = 47
    WLAN_INFO_RSN = 48,
    // RESERVED = 49
    WLAN_INFO_EXT_RATES = 50,
    // RESERVED = 51 - 126
    WLAN_INFO_EXT_CAPS = 127,
    // RESERVED = 128 - 220
    WLAN_INFO_VENDOR = 221
    // RESERVED = 222 - 225
} en_wlan_info;

// Dot11 info array structure
typedef struct {
    gchar* name;
    guint8 id;
    guint size_min;
    guint size_max;
} st_wlan_info;

// Dot11 info array data
#undef BMAP
#define BMAP(a, smin, smax) {#a, a, smin, smax}
st_wlan_info wlan_info[] = {
    BMAP(WLAN_INFO_SSID, 2, 34),
    BMAP(WLAN_INFO_RATES, 3, 10),
    BMAP(WLAN_INFO_FH_PARAM, 7, 7),
    BMAP(WLAN_INFO_DS_PARAM, 3, 3),
    BMAP(WLAN_INFO_CF_PARAM, 8, 8),
    BMAP(WLAN_INFO_TIM, 6, 256),
    BMAP(WLAN_INFO_IBSS_PARAM, 4, 4),
    BMAP(WLAN_INFO_COUNTRY, 8, 256),
    BMAP(WLAN_INFO_HOP_PARAM, 4, 4),
    BMAP(WLAN_INFO_HOP_TABLE, 6, 256),
    BMAP(WLAN_INFO_REQUEST, 2, 256),
    BMAP(WLAN_INFO_BSS_LOAD, 7, 7),
    BMAP(WLAN_INFO_EDCA_PARAM, 20, 20),
    BMAP(WLAN_INFO_TSPEC, 57, 57),
    BMAP(WLAN_INFO_TCLAS, 2, 257),
    BMAP(WLAN_INFO_SCHEDULE, 16, 16),
    BMAP(WLAN_INFO_CHALLENGE, 3, 255),
    BMAP(WLAN_INFO_POWER_CONST, 3, 3),
    BMAP(WLAN_INFO_POWER_CAPS, 4, 4),
    BMAP(WLAN_INFO_TPC_REQUEST, 2, 2),
    BMAP(WLAN_INFO_TPC_REPORT, 4, 4),
    BMAP(WLAN_INFO_SUPPORT_CHAN, 4, 256),
    BMAP(WLAN_INFO_CHAN_SWITCH, 5, 5),
    BMAP(WLAN_INFO_MEAS_REQUEST, 5, 16),
    BMAP(WLAN_INFO_MEAS_REPORT, 5, 24),
    BMAP(WLAN_INFO_QUIET, 8, 8),
    BMAP(WLAN_INFO_IBSS_DFS, 10, 255),
    BMAP(WLAN_INFO_ERP_INFO, 3, 3),
    BMAP(WLAN_INFO_TS_DELAY, 6, 6),
    BMAP(WLAN_INFO_TCLAS_PROC, 3, 3),
    BMAP(WLAN_INFO_QOS_CAPS, 3, 3),
    BMAP(WLAN_INFO_RSN, 36, 256),
    BMAP(WLAN_INFO_EXT_RATES, 3, 257),
    BMAP(WLAN_INFO_EXT_CAPS, 2, 257),
    BMAP(WLAN_INFO_VENDOR, 3, 257),
    { NULL }
};

// Beacon capability flags
#define WLAN_BEACON_CAPS_ESS BIT(0)
#define WLAN_BEACON_CAPS_IBSS BIT(1)
#define WLAN_BEACON_CAPS_CFPOLL BIT(2)
#define WLAN_BEACON_CAPS_CFPREQ BIT(3)
#define WLAN_BEACON_CAPS_PRIVACY BIT(4)
#define WLAN_BEACON_CAPS_SHORTPRE BIT(5)
#define WLAN_BEACON_CAPS_PBCC BIT(6)
#define WLAN_BEACON_CAPS_CHANAGILE BIT(7)
#define WLAN_BEACON_CAPS_SPECTRUM BIT(8)
#define WLAN_BEACON_CAPS_QOS BIT(9)
#define WLAN_BEACON_CAPS_SHORTSLOT BIT(10)
#define WLAN_BEACON_CAPS_APSD BIT(11)
#define WLAN_BEACON_CAPS_RESERVED BIT(12)
#define WLAN_BEACON_CAPS_DSSSOFDM BIT(13)
#define WLAN_BEACON_CAPS_DELAYACK BIT(14)
#define WLAN_BEACON_CAPS_IMMEDACK BIT(15)

// Dot11 beacon structure
typedef struct {
    // Timestamp
    guint8 b_timestamp[8];
    // Beacon interval
    guint16 b_interval;
    // Beacon capabilities (IEEE802.11-2007: page 88)
    guint16 b_caps;
    // * ESS ? AP : STA
    // * IBSS ? STA : AP
    // * CFPOLL
    // * CFPREQ
    // * PRIVACY - encryption related, complicated usage
    // * SHORTPRE - set on beacon frames
    // * PBCC
    // * CHANAGILE
    // * SPECTRUM
    // * QOS
    // * SHORTSLOT
    // * APSD
    // * DSSSOFDM
    // * DELAYACK
    // * IMMEDACK
    
    // Fields
    st_wlan_field* f_ssid; // Service Set Identifier (SSID)
    st_wlan_field* f_rates; // Supported rates
    st_wlan_field* f_freqhop; // Frequency-Hopping (FH) Parameter Set
    st_wlan_field* f_ds_param; // DS Parameter Set
    st_wlan_field* f_cf_param; // CF Parameter Set
    st_wlan_field* f_ibss_param; // IBSS Parameter Set
    st_wlan_field* f_tim; // Traffic indication map (TIM)
    st_wlan_field* f_country; // Country
    st_wlan_field* f_fh_param; // FH Parameters
    st_wlan_field* f_fh_pattern; // FH Pattern Table
    st_wlan_field* f_powerconst; // Power Constraint
    st_wlan_field* f_channelswitch; // Channel Switch Announcement
    st_wlan_field* f_quiet; // Quiet
    st_wlan_field* f_ibss_dfs; // IBSS DFS
    st_wlan_field* f_tpc_report; // TPC Report
    st_wlan_field* f_erp_info; // ERP Information
    st_wlan_field* f_ext_rates; // Extended Supported Rates
    st_wlan_field* f_rsn; // RSN
    st_wlan_field* f_bss_load; // BSS Load
    st_wlan_field* f_edca_param; // EDCA Parameter Set
    st_wlan_field* f_qos_caps; // QoS Capability
    st_wlan_field* f_vendor; // Vendor Specific
} st_wlan_beacon;

// Functions
void pck_ieee80211_read(st_ao_packet* pck)
{
    // Size check
	if (pck->m2_size >= sizeof(struct ieee80211_hdr)) {
	
	    // Set type
	    pck->m2_type = AO_M2_IEEE80211;
	    
	    // Ieee80211 header
	    guint32 hdr_offset = sizeof(struct ieee80211_hdr);
	    pck->m2.dot11.iw = (struct ieee80211_hdr*) pck->m2_data;
	    struct ieee80211_hdr* hdr_iw = pck->m2.dot11.iw;
	    
	    // Data packets
	    if (hdr_iw->u1.fc.type == WLAN_FC_TYPE_MGMT) {
	    
	        // Management frame
	        pck->m2.dot11.mgmt = (struct ieee80211_mgmt*) (pck->m2_data + hdr_offset);
	        struct ieee80211_mgmt* hdr_mgmt = pck->m2.dot11.mgmt;
	        
	        // Select subtype
	        switch(hdr_iw->u1.fc.subtype) {
	            case WLAN_FC_SUBTYPE_ASSOCREQ:
	                hdr_offset += sizeof(hdr_mgmt->u.assoc_req);
	                break;
	            case WLAN_FC_SUBTYPE_ASSOCRESP:
	                hdr_offset += sizeof(hdr_mgmt->u.assoc_resp);
	                break;
	            case WLAN_FC_SUBTYPE_REASSOCREQ:
	                hdr_offset += sizeof(hdr_mgmt->u.reassoc_req);
	                break;
	            case WLAN_FC_SUBTYPE_REASSOCRESP:
	                hdr_offset += sizeof(hdr_mgmt->u.reassoc_resp);
	                break;
	            case WLAN_FC_SUBTYPE_PROBEREQ:
	                hdr_offset += sizeof(hdr_mgmt->u.probe_req);
	                break;
	            case WLAN_FC_SUBTYPE_PROBERESP:
	                //hdr_offset += sizeof(hdr_mgmt->u.probe_resp);
	                // Pretty much a copy of beacon
	                break;
	            case WLAN_FC_SUBTYPE_BEACON:
	                // Beacon frame
	                hdr_offset += sizeof(hdr_mgmt->u.beacon);
	                
	                // Beacon structure
	                st_wlan_beacon bcon;
	                memset(&bcon, 0, sizeof(st_wlan_beacon));
	                g_memmove(bcon.b_timestamp, hdr_mgmt->u.beacon.timestamp, sizeof(bcon.b_timestamp));
	                bcon.b_interval = hdr_mgmt->u.beacon.beacon_int;
	                bcon.b_caps = hdr_mgmt->u.beacon.capab_info;
	                
	                // Beacon fields
	                guint8* fptr = hdr_mgmt->u.beacon.variable;
	                guint32 fsize = pck->m2_size - hdr_offset;
	                void read_bfield(st_wlan_field** field, guint8** ptr, guint32* size) {
	                    // Defaults
	                    *field = NULL;
	                    
	                    // Size check
	                    if (*size < 2)
	                        return;
	                    
	                    // Find field type
	                    st_wlan_field* temp = (st_wlan_field*) *ptr;
	                    gint i = 0;
	                    while (wlan_info[i].name) {
	                        if (temp->id == wlan_info[i].id)
	                            break;
	                        i++;
	                    }
	                    if (!wlan_info[i].name) {
	                        *size = 0;
	                        return;
	                    }
	                    
	                    // Check size constraints
	                    if (temp->length < wlan_info[i].size_min - 2 ||
	                        temp->length > wlan_info[i].size_max - 2) {
	                        *size = 0;
	                        return;
	                    }
	                    
	                    // Check for buffer size
	                    if (temp->length + 2 > *size) {
	                        *size = 0;
	                        return;
	                    }
	                    *size -= 2;
	                    
	                    // Data
	                    (*field)->id = temp->id;
	                    (*field)->length = temp->length;
	                    if (*size)
	                        (*field)->data = *ptr + 2;
	                    else
    	                    (*field)->data = NULL;
    	                *ptr += temp->length + 2;
	                }
	                read_bfield(&bcon.f_ssid, &fptr, &size); // Service Set Identifier (SSID)
                    bcon.f_rates = fptr; // Supported rates
                    bcon.f_freqhop = fptr; // Frequency-Hopping (FH) Parameter Set
                    bcon.f_ds_param = fptr; // DS Parameter Set
                    bcon.f_cf_param = fptr; // CF Parameter Set
                    bcon.f_ibss_param = fptr; // IBSS Parameter Set
                    bcon.f_tim = fptr; // Traffic indication map (TIM)
                    bcon.f_country = fptr; // Country
                    bcon.f_fh_param = fptr; // FH Parameters
                    bcon.f_fh_pattern = fptr; // FH Pattern Table
                    bcon.f_powerconst = fptr; // Power Constraint
                    bcon.f_channelswitch = fptr; // Channel Switch Announcement
                    bcon.f_quiet; // Quiet
                    bcon.f_ibss_dfs; // IBSS DFS
                    bcon.f_tpc_report; // TPC Report
                    bcon.f_erp_info; // ERP Information
                    bcon.f_ext_rates; // Extended Supported Rates
                    bcon.f_rsn; // RSN
                    bcon.f_bss_load; // BSS Load
                    bcon.f_edca_param; // EDCA Parameter Set
                    bcon.f_qos_caps; // QoS Capability
                    bcon.f_vendor; // Vendor Specific
    
                    g_print("* ieee! da=%02x%02x%02x%02x%02x%02x, sa=%02x%02x%02x%02x%02x%02x, bssid=%02x%02x%02x%02x%02x%02x\n",
                        hdr_iw->addr1[0], hdr_iw->addr1[1], hdr_iw->addr1[2], hdr_iw->addr1[3], hdr_iw->addr1[4], hdr_iw->addr1[5],
                        hdr_iw->addr2[0], hdr_iw->addr2[1], hdr_iw->addr2[2], hdr_iw->addr2[3], hdr_iw->addr2[4], hdr_iw->addr2[5],
                        hdr_iw->addr3[0], hdr_iw->addr3[1], hdr_iw->addr3[2], hdr_iw->addr3[3], hdr_iw->addr3[4], hdr_iw->addr3[5]
                    );
	                
	                break;
                case WLAN_FC_SUBTYPE_ATIM:
                    //hdr_offset += 0; // No frame body for ATIM
	                break;
	            case WLAN_FC_SUBTYPE_DISASSOC:
	                hdr_offset += sizeof(hdr_mgmt->u.disassoc);
	                break;
	            case WLAN_FC_SUBTYPE_AUTH:
	                hdr_offset += sizeof(hdr_mgmt->u.auth);
	                break;
	            case WLAN_FC_SUBTYPE_DEAUTH:
	                hdr_offset += sizeof(hdr_mgmt->u.deauth);
	                break;
	        }
	    
	    } else if (hdr_iw->u1.fc.type == WLAN_FC_TYPE_CTRL) {
	    
	    } else if (hdr_iw->u1.fc.type == WLAN_FC_TYPE_DATA) {
	    
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
	                hdr_iw->u1.fc.subtype == WLAN_FC_SUBTYPE_QOSDATA ||
	                hdr_iw->u1.fc.subtype == WLAN_FC_SUBTYPE_QOSNULL
	            ) && (
	                pck->m2_size >= hdr_offset + sizeof(struct ieee80211_qos)
	            )) {
	            pck->m2.dot11.qos = (struct ieee80211_qos*)(pck->m2_data + hdr_offset);
	            hdr_offset += sizeof(struct ieee80211_qos);
	        }
	        
	        // LLC/SNAP handling
	        pck->m2.dot11.llc = NULL;
	        if (pck->m2_size >= hdr_offset + sizeof(struct libnet_802_2snap_hdr)) {
	            pck->m2.dot11.llc = (struct libnet_802_2snap_hdr*)(pck->m2_data + hdr_offset);
	            hdr_offset += sizeof(struct libnet_802_2snap_hdr);
	        }
	        
	        // Next layer
	        if (pck->m2.dot11.llc != NULL) {
	        
	            // Data
	            pck->m3_data = pck->m2_data + hdr_offset;
	            pck->m3_size = pck->m2_size - hdr_offset;
	        
	            // Process
	            switch (pck->m2.dot11.llc->snap_type) {
	                case LLC_TYPE_IPV4:
	                    pck_ipv4_read(pck);
	                    break;
	                case LLC_TYPE_IPV6:
	                    pck_ipv6_read(pck);
	                    break;
	            }
	                
		    }
		    
	    }
	}
}

void pck_ieee80211_free(st_ao_packet* pck)
{
    switch (pck->m3_type) {
        case AO_M3_IPV4:
            pck_ipv4_free(pck);
            break;
        case AO_M3_IPV6:
            pck_ipv6_free(pck);
            break;
    }
}

