/*
 * Airown - Context
 *
 * Copyright (C) 2011 sh0 <sh0@yutani.ee>
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

#ifndef H_AO_CONTEXT
#define H_AO_CONTEXT

// Int inc
#include "ao_config.h"

#include "ui_console.h"
#include "ui_ncurses.h"

#include "drv_lorcon.h"
#include "drv_pcap.h"
#include "drv_nl.h"

// Context class
class c_context {
    public:
        // Constructor and destructor
        c_context();
        ~c_context();
        
        // Init and end
        bool init(
            const gchar* conf_drv_rx,
            const gchar* conf_mode_rx,
            const gchar* conf_dev_rx,
            const gchar* conf_drv_tx,
            const gchar* conf_mode_tx,
            const gchar* conf_dev_tx
        );
        void end();
        
        // Run and kill
        void run();
        void kill();

    private:
        // Active
        bool m_active;
        
        // UI
        c_ui* m_ui;
        
        // Driver
        typedef enum {
            DRIVER_NONE = 0,
            DRIVER_PCAP,
            DRIVER_LORCON,
            DRIVER_NETLINK
        } en_driver;
        c_drv* m_rx_drv;
        en_driver m_rx_type;
        guint m_rx_mode;
        c_drv* m_tx_drv;
        en_driver m_tx_type;
        guint m_tx_mode;
        
        // Packets
        GList* m_pck_hw;
        
        /*
        // Libnet
        libnet_t* ln_inst;
        libnet_ptag_t ln_tcp_t;
        libnet_ptag_t ln_thd_t;
        libnet_ptag_t ln_ip_t;
        */
        
        // Mainloop
        GMainLoop* m_mainloop;
        static gboolean f_loop_idle(gpointer data);
};

#endif

