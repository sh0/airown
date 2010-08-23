/*
 * Airown - main
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

#ifndef H_AO_MAIN
#define H_AO_MAIN

// Int inc
#include "ao_config.h"

// Protocols
#define AO_PROTO_L2_IEEE80211 (1 << 0)
#define AO_PROTO_L3_IPV4 (1 << 1)
#define AO_PROTO_L3_IPV6 (1 << 2)
#define AO_PROTO_L3_ARP (1 << 3)
#define AO_PROTO_L4_TCP (1 << 4)
#define AO_PROTO_L4_UDP (1 << 5)
#define AO_PROTO_L5_PAYLOAD (1 << 6)
#define AO_PROTO_ALL (AO_PROTO_L2_IEEE80211 | AO_PROTO_L3_IPV4 | AO_PROTO_L3_IPV6 | AO_PROTO_L3_ARP | AO_PROTO_L4_TCP | AO_PROTO_L4_UDP | AO_PROTO_L5_PAYLOAD)

// Instance structure
struct t_ao_inst {
    // Lorcon
    lorcon_t* lor_ctx; // = NULL;
    // Libnet
    libnet_t* ln_inst; // = NULL;
    libnet_ptag_t ln_tcp_t; // = 0; // IMPORTANT!
    libnet_ptag_t ln_thd_t; // = 0; // IMPORTANT!
    libnet_ptag_t ln_ip_t; // = 0; // IMPORTANT!
    // Command line (main)
    gchar* cmd_iface; // = "wlan0";
    gchar* cmd_driver; // = NULL;
    gboolean cmd_drvlist; // = FALSE;
    gint cmd_channel; // = 0;
    gchar* cmd_payload; // = NULL;
    // Command line (debug)
    gchar* cmd_dbg_mask; // = NULL;
    gchar* cmd_dbg_show; // = NULL;
    gchar* cmd_dbg_dump; // = NULL;
    // Debug masks
    guint32 dbg_mask; // = 0;
    guint32 dbg_show; // = 0;
    guint32 dbg_dump; // = 0;

};
typedef struct t_ao_inst st_ao_inst;

// Instance data
extern st_ao_inst ao_inst;

// Functions
void ao_signal(int sig);

#endif

