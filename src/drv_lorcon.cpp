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

// Int inc
#include "ao_config.h"
#include "drv_lorcon.h"
#include "pck_main.h"

// Constructor and destructor
c_drv_lorcon::c_drv_lorcon(const gchar* dev, const gchar* drv, guint chan)
{
    // Deactive
    m_active = false;
    
    // Copy info
    g_assert(dev);
    m_info_dev = g_strdup(dev);
    m_info_drv = (drv ? g_strdup(drv) : NULL);
    m_info_chan = chan;
}

c_drv_lorcon::~c_drv_lorcon()
{
    // End
    if (m_active)
        end();
    
    // Free info
    g_free(m_info_dev);
    if (m_info_drv)
        g_free(m_info_drv);
}

// Init and end
bool c_drv_lorcon::init()
{
    // Check
    g_assert(!m_active);
    
    // Queues
    m_queue_rx = g_async_queue_new_full(c_drv_lorcon::f_delete_pck);
    m_queue_tx = g_async_queue_new_full(c_drv_lorcon::f_delete_pck);
    
    // Driver
	if (m_info_drv) {
	
	    // Find driver
		m_driver = lorcon_find_driver(m_info_drv);
		if (!m_driver) {
			g_critical("[drv] could not find driver %s for interface %s!", m_info_drv, m_info_dev);
			goto err_driver;
		}
		
	} else {
    
	    // Detect driver
		m_driver = lorcon_auto_driver(m_info_dev);
		if (!m_driver) {
			g_critical("[drv] could not detect driver for %s!", m_info_dev);
			goto err_driver;
		}
        
	}
    
    // Lorcon context
    m_lorcon = lorcon_create(m_info_dev, m_driver);
	if (!m_lorcon) {
		g_critical("[drv] failed to open lorcon context! device=%s, driver=%s", m_info_dev, m_driver->name);
		goto err_lorcon;
	}
    
	// Get MTU
	{
	    // Vars
	    gint rsock;
	    struct ifreq ifr;
	    
	    // Open socket
	    rsock = socket(AF_INET, SOCK_DGRAM, 0);
        if (rsock < 0) {
            g_critical("[drv] unable to create temporary socket!");
            goto err_mtu_sock;
        }
	
	    // Ioctl
        memset(&ifr, 0, sizeof(ifr));
        g_strlcpy(ifr.ifr_name, m_info_dev, IF_NAMESIZE);
        if ((ioctl(rsock, SIOCGIFMTU, &ifr)) == -1) {
            g_critical("[drv] unable to get interface mtu!");
            close(rsock);
            goto err_mtu_ioctl;
        } else {
            m_mtu = ifr.ifr_mtu;
        }
        
        // Close socket
        close(rsock);
    }
    
    // Open lorcon
	if (lorcon_open_injmon(m_lorcon) < 0) {
		g_critical(
		    "[drv] failed to open driver for monitoring! device=%s, driver=%s, error=%s",
		    lorcon_get_capiface(m_lorcon), m_driver->name, lorcon_get_error(m_lorcon)
		);
		goto err_injmon;
	}
    
    // Channel
    if (m_info_chan != 0) {
        if (lorcon_set_channel(m_lorcon, m_info_chan) < 0) {
            g_warning("[drv] failed to set channel! chan=%d, error=%s", m_info_chan, lorcon_get_error(m_lorcon));
        }
    }
    m_chan = lorcon_get_channel(m_lorcon);
    
    // Message
    g_message(
        "[drv] lorcon opened! device=%s, driver=%s, channel=%u, mtu=%d",
        lorcon_get_capiface(m_lorcon), m_driver->name, m_chan, m_mtu
    );
    
    // Thread
    {
        GError* err = NULL;
        m_thr_run = true;
        m_thr_dead = false;
        m_thr_mutex = g_mutex_new();
        m_thr_cond = g_cond_new();
        m_thr_thread = g_thread_create(f_loop, this, FALSE, &err);
        if (!m_thr_thread) {
            if (err) {
                g_critical("[drv] failed to create thread! error=%s", err->message);
                g_clear_error(&err);
            } else {
                g_critical("[drv] failed to create thread! error=unknown");
            }
            goto err_thread;
        }
    }
    
    // Activate and return
    m_active = true;
    return true;
    
    // Error
    err_thread:
        // Thread
        g_mutex_free(m_thr_mutex);
        g_cond_free(m_thr_cond);
        
    err_injmon:
    err_mtu_ioctl:
    err_mtu_sock:
        // Lorcon context
        lorcon_free(m_lorcon);
        
    err_lorcon:
        // Driver
        lorcon_free_driver_list(m_driver);
        
    err_driver:
        // Queues
        g_async_queue_unref(m_queue_rx);
        g_async_queue_unref(m_queue_tx);
        
        // Return
        return false;
}

void c_drv_lorcon::end()
{
    // Check
    g_assert(m_active);
    
    // Thread
    g_mutex_lock(m_thr_mutex);
    m_thr_run = false;
    while (!m_thr_dead)
        g_cond_wait(m_thr_cond, m_thr_mutex);
    g_mutex_unlock(m_thr_mutex);
    g_mutex_free(m_thr_mutex);
    g_cond_free(m_thr_cond);
    
    // Lorcon context
    lorcon_free(m_lorcon);
    
    // Driver
    lorcon_free_driver_list(m_driver);
    
    // Queues
    g_async_queue_unref(m_queue_rx);
    g_async_queue_unref(m_queue_tx);
    
    // Deactivate
    m_active = false;
}

// Output
void c_drv_lorcon::help()
{
    // Driver list
    g_message("[drv] lorcon drivers:");
    lorcon_driver_t* drv_list = lorcon_list_drivers();
    for (lorcon_driver_t* drv_iter = drv_list; drv_iter; drv_iter = drv_iter->next) {
        g_message("[drv] * %s - %s", drv_iter->name, drv_iter->details);
    }
    lorcon_free_driver_list(drv_list);
}

const gchar* c_drv_lorcon::name()
{
    // Check
    g_assert(m_active);
    
    // Return
    return lorcon_get_capiface(m_lorcon);
}

// Packets
st_pck_drv* c_drv_lorcon::pck_rx()
{
    // Check
    g_assert(m_active);
    
    // Pop data
    return (st_pck_drv*) g_async_queue_try_pop(m_queue_rx);
}

void c_drv_lorcon::pck_tx(st_pck_drv* data)
{
    // Check
    g_assert(m_active);
    
    // Push data
    g_async_queue_push(m_queue_tx, data);
}

// Loop functions
gpointer c_drv_lorcon::f_loop(gpointer user)
{
    // Instance
    c_drv_lorcon* ctx = (c_drv_lorcon*) user;
    
    // Packet loop
    while (true) {
        // Exit check
        g_mutex_lock(ctx->m_thr_mutex);
        if (!ctx->m_thr_run) {
            ctx->m_thr_dead = true;
            g_cond_signal(ctx->m_thr_cond);
            g_mutex_unlock(ctx->m_thr_mutex);
            return NULL;
        }
        g_mutex_unlock(ctx->m_thr_mutex);
        
        // Packet loop
        bool ok = true;
        while (ok) {
            // Ok
            ok = false;
            
            // Receive packet
            lorcon_packet_t* pck_lorcon = NULL;
            gint ret = lorcon_next_ex(ctx->m_lorcon, &pck_lorcon);
            if (ret > 0) {
                if (pck_lorcon) {
                    ok = true;
                    st_pck_drv* pck_drv = g_new(st_pck_drv, 1);
                    pck_drv->data = g_byte_array_new();
                    pck_drv->type = LAYER_80211_PCK;
                    pck_drv->driver = ctx;
                    g_byte_array_append(pck_drv->data, pck_lorcon->packet_raw, pck_lorcon->length);
                    g_async_queue_push(ctx->m_queue_rx, pck_drv);
                    lorcon_packet_set_freedata(pck_lorcon, FALSE);
                    lorcon_packet_free(pck_lorcon);
                }
            } else if (ret < 0) {
                // Give error
                if (ret == -1) {
                    g_critical("[drv] error reading packet! error=%s", lorcon_get_error(ctx->m_lorcon));
                } else if (ret == -2) {
                    g_critical("[drv] read all packets from savefile!");
                } else {
                    g_critical("[drv] error reading packet! error=%s", lorcon_get_error(ctx->m_lorcon));
                }
            
                // Exit loop
                g_mutex_lock(ctx->m_thr_mutex);
                ctx->m_thr_dead = true;
                g_cond_signal(ctx->m_thr_cond);
                g_mutex_unlock(ctx->m_thr_mutex);
                return NULL;
            }
            
            // Transmit packet
            st_pck_drv* pck_drv = (st_pck_drv*) g_async_queue_try_pop(ctx->m_queue_tx);
            if (pck_drv) {
                // Transmit
                ok = true;
                gint ret = lorcon_send_bytes(ctx->m_lorcon, pck_drv->data->len, pck_drv->data->data);
                if (ret < 0) {
                    // Message
                    g_warning("[drv] failed to send packet! size=%u, error=%s", pck_drv->data->len, lorcon_get_error(ctx->m_lorcon));
                    
                    // Delete
                    g_byte_array_unref(pck_drv->data);
                    g_free(pck_drv);
                
                    // Exit loop
                    g_mutex_lock(ctx->m_thr_mutex);
                    ctx->m_thr_dead = true;
                    g_cond_signal(ctx->m_thr_cond);
                    g_mutex_unlock(ctx->m_thr_mutex);
                    return NULL;
                }
                
                // Delete
                g_byte_array_unref(pck_drv->data);
                g_free(pck_drv);
            }
        }
    }
}

void c_drv_lorcon::f_delete_pck(gpointer data)
{
    // Free packet
    st_pck_drv* pck = (st_pck_drv*) data;
    g_byte_array_unref(pck->data);
    g_free(pck);
}

