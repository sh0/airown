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

// Int inc
#include "ao_config.h"
#include "ao_context.h"

// Constructor and destructor
c_context::c_context()
{
    // Deactive
    m_active = false;
}

c_context::~c_context()
{
    // End
    if (m_active)
        end();
}

// Init and end
bool c_context::init(
    const gchar* conf_drv_rx,
    const gchar* conf_mode_rx,
    const gchar* conf_dev_rx,
    const gchar* conf_drv_tx,
    const gchar* conf_mode_tx,
    const gchar* conf_dev_tx
) {
    // Check
    g_assert(!m_active);
    
    // UI
    m_ui = new c_ui_console();
    if (!m_ui->init()) {
        g_critical("[sys] failed to open ui, aborting!");
        goto err_ui;
    }
    
    // Banner
    g_message("[sys] airown " AO_VERSION " (build " __TIME__ " " __DATE__ ")");
    
    // Packets
    m_pck_hw = NULL;
    
    // Driver init
    m_rx_drv = NULL;
    m_rx_type = DRIVER_NONE;
    m_tx_drv = NULL;
    m_tx_type = DRIVER_NONE;
    
    // RX driver and mode
    if (!g_strcmp0(conf_drv_rx, "pcap")) {
        #ifdef PCAP_FOUND
            m_rx_type = DRIVER_PCAP;
            if (!g_strcmp0(conf_mode_rx, "file")) {
                m_rx_mode = PCAP_MODE_FILE;
                g_message("[sys] rx enabled: driver=pcap, mode=file, file=%s", conf_dev_rx);
            } else if (!g_strcmp0(conf_mode_rx, "dev")) {
                m_rx_mode = PCAP_MODE_DEV;
                g_message("[sys] rx enabled: driver=pcap, mode=dev, device=%s", conf_dev_rx);
            } else {
                g_critical("[sys] driver pcap does not support rx mode %s, please use either \"file\" or \"dev\"!", conf_mode_rx);
                goto err_drv_find;
            }
        #else
            g_critical("[sys] pcap driver not enabled in this build, choose another driver or rebuild airown!");
            goto err_drv_find;
        #endif
    } else if (!g_strcmp0(conf_drv_rx, "lorcon")) {
        #ifdef LORCON_FOUND
            m_rx_type = DRIVER_LORCON;
            if (!g_strcmp0(conf_mode_rx, "dev")) {
                g_message("[sys] rx enabled: driver=lorcon, mode=dev, device=%s", conf_dev_rx);
            } else {
                g_critical("[sys] driver lorcon does not support rx mode %s, please use \"dev\"!", conf_mode_rx);
                goto err_drv_find;
            }
        #else
            g_critical("[sys] lorcon driver not enabled in this build, choose another driver or rebuild airown!");
            goto err_drv_find;
        #endif
    } else if (!g_strcmp0(conf_drv_rx, "netlink")) {
        #ifdef NETLINK_FOUND
            m_rx_type = DRIVER_NETLINK;
            if (!g_strcmp0(conf_mode_rx, "dev")) {
                g_message("[sys] rx enabled: driver=netlink, mode=dev, device=%s", conf_dev_rx);
            } else {
                g_critical("[sys] driver netlink does not support rx mode %s, please use \"dev\"!", conf_mode_rx);
                goto err_drv_find;
            }
        #else
            g_critical("[sys] netlink driver not enabled in this build, choose another driver or rebuild airown!");
            goto err_drv_find;
        #endif
    }
    
    // TX driver and mode
    if (!g_strcmp0(conf_drv_tx, "pcap")) {
        #ifdef PCAP_FOUND
            m_tx_type = DRIVER_PCAP;
            if (!g_strcmp0(conf_mode_tx, "file")) {
                m_tx_mode = PCAP_MODE_FILE;
                g_message("[sys] tx enabled: driver=pcap, mode=file, file=%s", conf_dev_tx);
            } else {
                g_critical("[sys] driver pcap does not support tx mode %s, please use \"file\"!", conf_mode_tx);
                goto err_drv_find;
            }
        #else
            g_critical("[sys] pcap driver not enabled in this build, choose another driver or rebuild airown!");
            goto err_drv_find;
        #endif
    } else if (!g_strcmp0(conf_drv_tx, "lorcon")) {
        #ifdef LORCON_FOUND
            m_tx_type = DRIVER_LORCON;
            if (!g_strcmp0(conf_mode_tx, "dev")) {
                g_message("[sys] tx enabled: driver=lorcon, mode=dev, device=%s", conf_dev_tx);
            } else {
                g_critical("[sys] driver lorcon does not support tx mode %s, please use \"dev\"!", conf_mode_tx);
                goto err_drv_find;
            }
        #else
            g_critical("[sys] lorcon driver not enabled in this build, choose another driver or rebuild airown!");
            goto err_drv_find;
        #endif
    } else if (!g_strcmp0(conf_drv_tx, "netlink")) {
        #ifdef NETLINK_FOUND
            m_tx_type = DRIVER_NETLINK;
            if (!g_strcmp0(conf_mode_tx, "dev")) {
                g_message("[sys] tx enabled: driver=netlink, mode=dev, device=%s", conf_dev_tx);
            } else {
                g_critical("[sys] driver netlink does not support tx mode %s, please use \"dev\"!", conf_mode_tx);
                goto err_drv_find;
            }
        #else
            g_critical("[sys] netlink driver not enabled in this build, choose another driver or rebuild airown!");
            goto err_drv_find;
        #endif
    }
    
    // Check drivers
    if (m_rx_type == DRIVER_NONE && m_tx_type == DRIVER_NONE) {
        g_critical("[sys] no specified rx or tx drivers found! rx_drv=%s, tx_drv=%s", conf_drv_rx, conf_drv_tx);
        goto err_drv_find;
    }
    
    // Pcap
    #ifdef PCAP_FOUND
        if (m_rx_type == DRIVER_PCAP || m_tx_type == DRIVER_PCAP) {
            if (m_rx_type == DRIVER_PCAP && m_tx_type == DRIVER_PCAP) {
                m_tx_drv = m_rx_drv = new c_drv_pcap(conf_dev_rx, m_rx_mode, conf_dev_tx, m_tx_mode);
                if (!m_rx_drv->init())
                    goto err_drv_init;
            } else if (m_rx_type == DRIVER_PCAP) {
                m_rx_drv = new c_drv_pcap(conf_dev_rx, m_rx_mode, conf_dev_tx, m_tx_mode);
                if (!m_rx_drv->init())
                    goto err_drv_init;
            } else if (m_tx_type == DRIVER_PCAP) {
                m_tx_drv = new c_drv_pcap(conf_dev_rx, m_rx_mode, conf_dev_tx, m_tx_mode);
                if (!m_tx_drv->init())
                    goto err_drv_init;
            }
        }
    #endif
    
    // Lorcon
    #ifdef LORCON_FOUND
        if (m_rx_type == DRIVER_LORCON || m_tx_type == DRIVER_LORCON) {
            if (m_rx_type == DRIVER_LORCON && m_tx_type == DRIVER_LORCON && !g_strcmp0(conf_dev_rx, conf_dev_tx)) {
                m_tx_drv = m_rx_drv = new c_drv_lorcon(conf_dev_rx, NULL, 0);
                if (!m_rx_drv->init())
                    goto err_drv_init;
            } else if (m_rx_type == DRIVER_LORCON && m_tx_type == DRIVER_LORCON) {
                m_rx_drv = new c_drv_lorcon(conf_dev_rx, NULL, 0);
                if (!m_rx_drv->init())
                    goto err_drv_init;
                m_tx_drv = new c_drv_lorcon(conf_dev_tx, NULL, 0);
                if (!m_tx_drv->init())
                    goto err_drv_init;
            } else if (m_rx_type == DRIVER_LORCON) {
                m_rx_drv = new c_drv_lorcon(conf_dev_rx, NULL, 0);
                if (!m_rx_drv->init())
                    goto err_drv_init;
            } else if (m_tx_type == DRIVER_LORCON) {
                m_tx_drv = new c_drv_lorcon(conf_dev_tx, NULL, 0);
                if (!m_tx_drv->init())
                    goto err_drv_init;
            }
        }
    #endif
    
    // Netlink
    #ifdef NETLINK_FOUND
        if (m_rx_type == DRIVER_NETLINK || m_tx_type == DRIVER_NETLINK) {
            if (m_rx_type == DRIVER_NETLINK && m_tx_type == DRIVER_NETLINK && !g_strcmp0(conf_dev_rx, conf_dev_tx)) {
                m_tx_drv = m_rx_drv = new c_drv_netlink(conf_dev_rx);
                if (!m_rx_drv->init())
                    goto err_drv_init;
            } else if (m_rx_type == DRIVER_NETLINK && m_tx_type == DRIVER_NETLINK) {
                m_rx_drv = new c_drv_netlink(conf_dev_rx);
                if (!m_rx_drv->init())
                    goto err_drv_init;
                m_tx_drv = new c_drv_netlink(conf_dev_tx);
                if (!m_tx_drv->init())
                    goto err_drv_init;
            } else if (m_rx_type == DRIVER_NETLINK) {
                m_rx_drv = new c_drv_netlink(conf_dev_rx);
                if (!m_rx_drv->init())
                    goto err_drv_init;
            } else if (m_tx_type == DRIVER_NETLINK) {
                m_tx_drv = new c_drv_netlink(conf_dev_tx);
                if (!m_tx_drv->init())
                    goto err_drv_init;
            }
        }
    #endif

	/*
	// Libnet
	char lnet_err[LIBNET_ERRBUF_SIZE];
    ao_inst.ln_inst = libnet_init(LIBNET_LINK_ADV, "lo", lnet_err);
    if (ao_inst.ln_inst == NULL) {
        g_message("[sys] failed to init libnet! err=%s", lnet_err);
        exit(1);
    }
    */
    
    // Mainloop
    m_kill = false;
    m_mainloop = g_main_loop_new(NULL, FALSE);
    g_idle_add(c_context::f_loop_idle, this);
    
    // Activate and return
    m_active = true;
    return true;
    
    // Errors
    err_drv_init:
        // Driver
        if (m_rx_drv && m_tx_drv && m_rx_drv == m_tx_drv) {
            delete m_rx_drv;
        } else if (m_rx_drv && m_tx_drv) {
            delete m_rx_drv;
            delete m_tx_drv;
        } else if (m_rx_drv) {
            delete m_rx_drv;
        } else if (m_tx_drv) {
            delete m_tx_drv;
        }
        
    err_drv_find:
    err_ui:
        // UI
        delete m_ui;
        
        // Return
        return false;
}

void c_context::end()
{
    // Check
    g_assert(m_active);
    
    // Mainloop
    g_main_loop_unref(m_mainloop);
    
    // Driver
    if (m_rx_drv && m_tx_drv && m_rx_drv == m_tx_drv) {
        delete m_rx_drv;
    } else if (m_rx_drv && m_tx_drv) {
        delete m_rx_drv;
        delete m_tx_drv;
    } else if (m_rx_drv) {
        delete m_rx_drv;
    } else if (m_tx_drv) {
        delete m_tx_drv;
    }
    
    // UI
    delete m_ui;
    
    // Deactivate
    m_active = false;
}

// Run and kill
void c_context::run()
{
    // Check
    g_assert(m_active);
    
    // Run mainloop
    g_main_loop_run(m_mainloop);
}

void c_context::kill()
{
    // Check
    g_assert(m_active);
    
    // Kill
    m_kill = true;
}

// Mainloop
gboolean c_context::f_loop_idle(gpointer data)
{
    // Context
    c_context* ctx = (c_context*) data;
    
    // Process packets
    if (ctx->m_rx_drv) {
        st_pck_drv* pck_drv = ctx->m_rx_drv->pck_rx();
        if (pck_drv) {
            c_layer_hw* pck_hw = new c_layer_hw();
            if (pck_hw->init_unpack(pck_drv)) {
                ctx->m_pck_hw = g_list_append(ctx->m_pck_hw, pck_hw);
            } else {
                delete pck_hw;
            }
        }
    }
    
    // Kill
    if (ctx->m_kill)
        g_main_loop_quit(ctx->m_mainloop);
    
    // Return
    return TRUE;
}


