/*
 * Airown - Driver - Lorcon
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

#ifndef H_DRV_LORCON
#define H_DRV_LORCON

// Int inc
#include "ao_config.h"
#include "drv_main.h"

// Ext inc
#define protected protected_c
extern "C" {
#include <lorcon.h>
#include <lorcon_ieee80211.h>
#include <lorcon_packasm.h>
#include <lorcon_forge.h>
}
#undef protected

// Driver class
class c_drv_lorcon : public c_drv {
    public:
        // Constructor and destructor
        c_drv_lorcon(const gchar* dev, const gchar* drv, guint chan);
        ~c_drv_lorcon();
        
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
        
        // Lorcon
        lorcon_t* m_lorcon;
        lorcon_driver_t* m_driver;
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

#endif

