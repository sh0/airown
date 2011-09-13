/*
 * Airown - Driver - 802.11 netlink
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

#ifndef H_DRV_NL
#define H_DRV_NL

// Int inc
#include "ao_config.h"
#include "drv_main.h"
#include "pck_main.h"

// Enable check
#ifdef NETLINK_FOUND

// Driver class
class c_drv_netlink : public c_drv {
    public:
        // Constructor and destructor
        c_drv_netlink(const gchar* dev);
        ~c_drv_netlink();
        
        // Init and end
        bool init();
        void end();
        
        // Output
        void help();
        const gchar* name();
        
        // Packets
        st_pck_drv* pck_rx();
        void pck_tx(st_pck_drv* data);

    private:
        // Active
        bool m_active;
        
        // Info
        gchar* m_info_dev;
        gchar* m_info_drv;
        guint m_info_chan;
        
        // Netlink
        
        guint m_mtu;
        gint m_chan;
        
        // Thread
        GThread* m_thr_thread;
        GMutex* m_thr_mutex;
        GCond* m_thr_cond;
        bool m_thr_run;
        bool m_thr_dead;
        
        // Queues
        GAsyncQueue* m_queue_rx;
        GAsyncQueue* m_queue_tx;
        
        // Loop functions
        static gpointer f_loop(gpointer user);
        static void f_delete_pck(gpointer data);
};

#endif // NETLINK_FOUND
#endif // H_DRV_NL

