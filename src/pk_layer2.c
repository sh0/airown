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

