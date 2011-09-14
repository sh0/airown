/*
 * Airown - Main
 *
 * Copyright (C) 2010-2011 sh0 <sh0@yutani.ee>
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
#include "ao_context.h"
#include "ui_console.h"
#include "drv_pcap.h"
#include "drv_lorcon.h"
#include "drv_nl.h"

// Instance
static c_context* ao_inst = NULL;

// Command-line


// Signal
static void ao_signal(int sig)
{
    if (sig == SIGINT) {
        if (ao_inst)
            ao_inst->kill();
    } else if (sig == SIGWINCH) {
        //ao_inst->sig_winch();
    }
}

// Main
int main(int argc, char* argv[])
{
    // Setup cmd
    const gchar* cmd_drv_rx = "pcap";
    const gchar* cmd_mode_rx = "file";
    const gchar* cmd_dev_rx = "test-rx.pcap";
    const gchar* cmd_drv_tx = "pcap";
    const gchar* cmd_mode_tx = "file";
    const gchar* cmd_dev_tx = "test-tx.pcap";
    GOptionEntry cmd_entry_main[] = {
        { "rx-drv", '\0', 0, G_OPTION_ARG_STRING, &cmd_drv_rx, "RX driver" },
        { "rx-mode", '\0', 0, G_OPTION_ARG_STRING, &cmd_mode_rx, "RX mode (dev / file)" },
        { "rx-dev", '\0', 0, G_OPTION_ARG_STRING, &cmd_dev_rx, "RX device (wlan0 / eth0 / file.pcap)" },
        { "tx-drv", '\0', 0, G_OPTION_ARG_STRING, &cmd_drv_tx, "TX driver" },
        { "tx-mode", '\0', 0, G_OPTION_ARG_STRING, &cmd_mode_tx, "TX mode (dev / file)" },
        { "tx-dev", '\0', 0, G_OPTION_ARG_STRING, &cmd_dev_tx, "TX device (wlan0 / eth0 / file.pcap)" },
        { NULL }
    };
    gboolean cmd_list_pcap = false;
    gboolean cmd_list_lorcon = false;
    gboolean cmd_list_netlink = false;
    GOptionEntry cmd_entry_driver[] = {
        #ifdef PCAP_FOUND
            { "list-pcap", '\0', 0, G_OPTION_ARG_NONE, &cmd_list_pcap, "PCAP device list" },
        #endif
        #ifdef LORCON_FOUND
            { "list-lorcon", '\0', 0, G_OPTION_ARG_NONE, &cmd_list_lorcon, "LORCON device list" },
        #endif
        #ifdef NETLINK_FOUND
            { "list-netlink", '\0', 0, G_OPTION_ARG_NONE, &cmd_list_netlink, "NETLINK device list" },
        #endif
        { NULL }
    };
    
    // Parse cmd
    GError* cmd_error = NULL;
    GOptionContext* cmd_ctx = g_option_context_new("- packet injection tool");
    g_option_context_add_main_entries(cmd_ctx, cmd_entry_main, NULL);
    GOptionGroup* cmd_lgrp = g_option_group_new("list", "Driver devices", "Driver devices", NULL, NULL);
    g_option_group_add_entries(cmd_lgrp, cmd_entry_driver);
    g_option_context_add_group(cmd_ctx, cmd_lgrp);
    g_option_context_set_description(cmd_ctx,
        "Supported drivers:\n"
        #ifdef PCAP_FOUND
            "  * pcap\n"
        #endif
        #ifdef LORCON_FOUND
            "  * lorcon\n"
        #endif
        #ifdef NETLINK_FOUND
            "  * netlink\n"
        #endif
    );
    if (!g_option_context_parse(cmd_ctx, &argc, &argv, &cmd_error)) {
        g_message("Option parsing failed: %s", cmd_error->message);
        exit(1);
    }

    // Signal setup
    if (signal(SIGINT, ao_signal) == SIG_ERR) {
        g_critical("[sys] failed to set SIGINT signal handler!");
    } else if (signal(SIGWINCH, ao_signal) == SIG_ERR) {
        g_critical("[sys] failed to set SIGWINCH signal handler!");
    }
    
    // Threads
    g_thread_init(NULL);
    
    // Lists
    if (cmd_list_pcap || cmd_list_lorcon || cmd_list_netlink) {
        // Console
        c_ui_console* ui = new c_ui_console();
        ui->init();
        
        // Show
        if (cmd_list_pcap) {
            #ifdef PCAP_FOUND
                c_drv_pcap::help();
            #else
                g_critical("Pcap driver not compiled in this binary!");
            #endif
        }
        if (cmd_list_lorcon) {
            #ifdef LORCON_FOUND
                c_drv_lorcon::help();
            #else
                g_critical("Lorcon driver not compiled in this binary!");
            #endif
        }
        if (cmd_list_netlink) {
            #ifdef NETLINK_FOUND
                c_drv_netlink::help();
            #else
                g_critical("Netlink driver not compiled in this binary!");
            #endif
        }
        
        // Quit
        exit(0);
    }
    
    // Context
    ao_inst = new c_context();
    if (ao_inst->init(cmd_drv_rx, cmd_mode_rx, cmd_dev_rx, cmd_drv_tx, cmd_mode_tx, cmd_dev_tx)) {
        ao_inst->run();
    }

	// Return
	return 0;
}

