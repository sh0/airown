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
        { "rx-drv", '\0', 0, G_OPTION_ARG_STRING, &cmd_drv_rx, "RX driver (pcap / lorcon)" },
        { "rx-mode", '\0', 0, G_OPTION_ARG_STRING, &cmd_mode_rx, "RX mode (hw / file)" },
        { "rx-dev", '\0', 0, G_OPTION_ARG_STRING, &cmd_dev_rx, "RX device (wlan0 / eth0 / file.pcap)" },
        { "tx-drv", '\0', 0, G_OPTION_ARG_STRING, &cmd_drv_tx, "TX driver (pcap / lorcon)" },
        { "tx-mode", '\0', 0, G_OPTION_ARG_STRING, &cmd_mode_tx, "TX mode (hw / file)" },
        { "tx-dev", '\0', 0, G_OPTION_ARG_STRING, &cmd_dev_tx, "TX device (wlan0 / eth0 / file.pcap)" },
        { NULL }
    };
    
    // Parse cmd
    GError* cmd_error = NULL;
    GOptionContext* cmd_ctx;

    cmd_ctx = g_option_context_new("- packet injection tool");
    g_option_context_add_main_entries(cmd_ctx, cmd_entry_main, NULL);
    //g_option_context_set_description(cmd_ctx, "");
    
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
    
    // Context
    ao_inst = new c_context();
    if (ao_inst->init(cmd_drv_rx, cmd_mode_rx, cmd_dev_rx, cmd_drv_tx, cmd_mode_tx, cmd_dev_tx)) {
        ao_inst->run();
    }

	// Return
	return 0;
}

