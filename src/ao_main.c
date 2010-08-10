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

// Int inc
#include "ao_config.h"
#include "ao_main.h"
#include "ao_packet.h"
#include "ao_util.h"
#include "ao_payload.h"

// Data
st_ao_inst ao_inst;

// Command-line
static GOptionEntry cmd_entry_main[] = {
    { "iface", 'i', 0, G_OPTION_ARG_STRING, &(ao_inst.cmd_iface), "Interface name (default is wlan0)" },
    { "driver", 'd', 0, G_OPTION_ARG_STRING, &(ao_inst.cmd_driver), "Driver name (default is to guess)" },
    { "drvlist", 'l', 0, G_OPTION_ARG_NONE, &(ao_inst.cmd_drvlist), "Show avilable drivers (and exit afterwards)" },
    { "channel", 'c', 0, G_OPTION_ARG_INT, &(ao_inst.cmd_channel), "Channel number (by default hop between channels)" },
    { "payload", 'p', 0, G_OPTION_ARG_FILENAME, &(ao_inst.cmd_payload), "Payload configuration file" },
    { NULL }
};
static GOptionEntry cmd_entry_debug[] = {
    { "dbg-mask", 'm', 0, G_OPTION_ARG_STRING, &(ao_inst.cmd_dbg_mask), "Protocols to be logged (default=none)" },
    { "dbg-show", 's', 0, G_OPTION_ARG_STRING, &(ao_inst.cmd_dbg_show), "Protocol data to show in log (default=all)" },
    { "dbg-dump", 'u', 0, G_OPTION_ARG_STRING, &(ao_inst.cmd_dbg_dump), "Dump raw data about protocols (default=none)" },
    { NULL }
};

// Main
int main(int argc, char* argv[]) {

    // Instance defaults
    ao_inst.lor_ctx = NULL;
    ao_inst.ln_inst = NULL;
    ao_inst.ln_tcp_t = 0;
    ao_inst.ln_ip_t = 0;
    ao_inst.cmd_iface = "wlan0";
    ao_inst.cmd_driver = NULL;
    ao_inst.cmd_drvlist = FALSE;
    ao_inst.cmd_channel = 0;
    ao_inst.cmd_payload = NULL;
    ao_inst.cmd_dbg_mask = NULL;
    ao_inst.cmd_dbg_show = NULL;
    ao_inst.cmd_dbg_dump = NULL;
    ao_inst.dbg_mask = 0;
    ao_inst.dbg_show = AO_PROTO_ALL;
    ao_inst.dbg_dump = 0;

    // Command-line
    GError* cmd_error = NULL;
    GOptionContext* cmd_ctx;

    cmd_ctx = g_option_context_new("- 802.11 packet injection tool");
    g_option_context_add_main_entries(cmd_ctx, cmd_entry_main, NULL);
    
    GOptionGroup* cmd_grp_dbg = g_option_group_new("debug", "Debugging Options:", "Debugging options", NULL, NULL);
    g_option_group_add_entries(cmd_grp_dbg, cmd_entry_debug);
    g_option_context_add_group(cmd_ctx, cmd_grp_dbg);
    g_option_context_set_description(cmd_ctx, "Avilable protocols: ieee80211, ipv4, ipv6, arp, tcp, udp");
    
    if (!g_option_context_parse(cmd_ctx, &argc, &argv, &cmd_error)) {
        g_print("Option parsing failed: %s\n", cmd_error->message);
        exit(1);
    }
    
    // Debug mask list
    if (ao_inst.cmd_dbg_mask != NULL) {
        gchar** dmask = g_strsplit(ao_inst.cmd_dbg_mask, ",", 0);
        gint i = 0;
        while (dmask[i] != NULL) {
            if (g_strcmp0(dmask[i], "ieee80211") == 0) {
                ao_inst.dbg_mask |= AO_PROTO_L2_IEEE80211;
            } else if (g_strcmp0(dmask[i], "ipv4") == 0) {
                ao_inst.dbg_mask |= AO_PROTO_L3_IPV4;
            } else if (g_strcmp0(dmask[i], "ipv6") == 0) {
                ao_inst.dbg_mask |= AO_PROTO_L3_IPV6;
            } else if (g_strcmp0(dmask[i], "arp") == 0) {
                ao_inst.dbg_mask |= AO_PROTO_L3_ARP;
            } else if (g_strcmp0(dmask[i], "tcp") == 0) {
                ao_inst.dbg_mask |= AO_PROTO_L4_TCP;
            } else if (g_strcmp0(dmask[i], "udp") == 0) {
                ao_inst.dbg_mask |= AO_PROTO_L4_UDP;
            } else if (g_strcmp0(dmask[i], "payload") == 0) {
                ao_inst.dbg_mask |= AO_PROTO_L5_PAYLOAD;
            } else if (g_strcmp0(dmask[i], "none") == 0) {
            } else {
                g_print("Unidentified protocol in dbg-mask! protocol=%s\n", dmask[i]);
                exit(1);
            }
            i++;
        }
    }
    
    // Debug show list
    if (ao_inst.cmd_dbg_show != NULL) {
        ao_inst.dbg_show = 0;
        gchar** dshow = g_strsplit(ao_inst.cmd_dbg_show, ",", 0);
        gint i = 0;
        while (dshow[i] != NULL) {
            if (g_strcmp0(dshow[i], "ieee80211") == 0) {
                ao_inst.dbg_show |= AO_PROTO_L2_IEEE80211;
            } else if (g_strcmp0(dshow[i], "ipv4") == 0) {
                ao_inst.dbg_show |= AO_PROTO_L3_IPV4;
            } else if (g_strcmp0(dshow[i], "ipv6") == 0) {
                ao_inst.dbg_show |= AO_PROTO_L3_IPV6;
            } else if (g_strcmp0(dshow[i], "arp") == 0) {
                ao_inst.dbg_show |= AO_PROTO_L3_ARP;
            } else if (g_strcmp0(dshow[i], "tcp") == 0) {
                ao_inst.dbg_show |= AO_PROTO_L4_TCP;
            } else if (g_strcmp0(dshow[i], "udp") == 0) {
                ao_inst.dbg_show |= AO_PROTO_L4_UDP;
            } else if (g_strcmp0(dshow[i], "payload") == 0) {
                ao_inst.dbg_show |= AO_PROTO_L5_PAYLOAD;
            } else if (g_strcmp0(dshow[i], "none") == 0) {
            } else {
                g_print("Unidentified protocol in dbg-show! protocol=%s\n", dshow[i]);
                exit(1);
            }
            i++;
        }
    }
    
    // Debug dump list
    if (ao_inst.cmd_dbg_dump != NULL) {
        gchar** ddump = g_strsplit(ao_inst.cmd_dbg_dump, ",", 0);
        gint i = 0;
        while (ddump[i] != NULL) {
            if (g_strcmp0(ddump[i], "ieee80211") == 0) {
                ao_inst.dbg_dump |= AO_PROTO_L2_IEEE80211;
            } else if (g_strcmp0(ddump[i], "ipv4") == 0) {
                ao_inst.dbg_dump |= AO_PROTO_L3_IPV4;
            } else if (g_strcmp0(ddump[i], "ipv6") == 0) {
                ao_inst.dbg_dump |= AO_PROTO_L3_IPV6;
            } else if (g_strcmp0(ddump[i], "arp") == 0) {
                ao_inst.dbg_dump |= AO_PROTO_L3_ARP;
            } else if (g_strcmp0(ddump[i], "tcp") == 0) {
                ao_inst.dbg_dump |= AO_PROTO_L4_TCP;
            } else if (g_strcmp0(ddump[i], "udp") == 0) {
                ao_inst.dbg_dump |= AO_PROTO_L4_UDP;
            } else if (g_strcmp0(ddump[i], "payload") == 0) {
                ao_inst.dbg_dump |= AO_PROTO_L5_PAYLOAD;
            } else if (g_strcmp0(ddump[i], "none") == 0) {
            } else {
                g_print("Unidentified protocol in dbg-dump! protocol=%s\n", ddump[i]);
                exit(1);
            }
            i++;
        }
    }

    // Driver list
    if (ao_inst.cmd_drvlist) {
        lorcon_driver_t* drv_list = lorcon_list_drivers();
        g_print("Supported LORCON drivers:\n");
        while (drv_list) {
	        g_print("* %-10.10s - %s\n", drv_list->name, drv_list->details);
	        drv_list = drv_list->next;
        }
        lorcon_free_driver_list(drv_list);
        exit(0);  
    }

    // Vars
	lorcon_driver_t* dri;

    // Payload
    if (ao_payload_init() == FALSE) {
        exit(1);
    }

    // Interface check
    if (ao_inst.cmd_iface == NULL || strlen(ao_inst.cmd_iface) == 0) {
        g_print("[sys] please specify interface!\n");
        exit(1);
    }
    
    // Channel check
    if (ao_inst.cmd_channel < 0 || ao_inst.cmd_channel > 200) {
        g_print("[chn] specified channel is out of bounds!\n");
        exit(1);
    }

    // Driver and interface
	if (ao_inst.cmd_driver != NULL) {
	
	    // Find driver
		dri = lorcon_find_driver(ao_inst.cmd_driver);
		if (dri == NULL) {
			printf("[drv] could not find driver %s for interface %s!\n", ao_inst.cmd_driver, ao_inst.cmd_iface);
			exit(1);
		}
		g_print("[drv] found driver %s for interface %s\n", ao_inst.cmd_driver, ao_inst.cmd_iface);
		
	} else {
	
	    // Detect driver
		dri = lorcon_auto_driver(ao_inst.cmd_iface);
		if (dri == NULL) {
			g_print("[drv] could not detect driver for %s!\n", ao_inst.cmd_iface);
			exit(1);
		}
		g_print("[drv] detected driver %s for interface %s\n", dri->name, ao_inst.cmd_iface);
	}

    // Create lorcon context
	if ((ao_inst.lor_ctx = lorcon_create(ao_inst.cmd_iface, dri)) == NULL) {
		g_print("[sys] failed to create context for %s %s!\n", ao_inst.cmd_iface, dri->name);
		exit(1);
	}

    // Open lorcon context
	if (lorcon_open_injmon(ao_inst.lor_ctx) < 0) {
		g_print("[sys] failed to open %s %s in injmon mode! error=%s\n", lorcon_get_capiface(ao_inst.lor_ctx), dri->name, lorcon_get_error(ao_inst.lor_ctx));
		exit(1);
	}

    // Free driver
	lorcon_free_driver_list(dri);
	
	// Libnet
	char lnet_err[LIBNET_ERRBUF_SIZE];
    ao_inst.ln_inst = libnet_init(LIBNET_LINK_ADV, "lo", lnet_err);
    if (ao_inst.ln_inst == NULL) {
        g_print("[sys] failed to init libnet! err=%s\n", lnet_err);
        exit(1);
    }
    
    // Channel
    if (ao_inst.cmd_channel != 0) {
        if (lorcon_set_channel(ao_inst.lor_ctx, ao_inst.cmd_channel) < 0) {
            g_print("[chn] failure! chan=%d, error=%s\n", ao_inst.cmd_channel, lorcon_get_error(ao_inst.lor_ctx));
        } else {
            g_print("[chn] selected channel %d\n", ao_inst.cmd_channel);
        }
    } else {
        g_print("[chn] floating!\n");
    }

    // Signal setup
    if (signal(SIGINT, ao_signal) == SIG_ERR) {
        g_print("Failed to set SIGINT signal handler!\n");
    }

    // Loop
    g_print("[sys] starting capture loop\n");
	lorcon_loop(ao_inst.lor_ctx, 0, ao_pck_loop, (u_char*) &ao_inst);

    // Release
    g_print("[sys] releasing capture device\n");
	lorcon_free(ao_inst.lor_ctx);
	
	// Return
	return 0;
}

void ao_signal(int sig)
{
    if (sig == SIGINT) {
        lorcon_breakloop(ao_inst.lor_ctx);
    }
}

