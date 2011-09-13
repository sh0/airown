/*
 * Airown - Driver - Pcap
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
#include "drv_pcap.h"

// Enable check
#ifdef PCAP_FOUND

// Constructor and destructor
c_drv_pcap::c_drv_pcap(const gchar* dev_rx, guint mode_rx, const gchar* dev_tx, guint mode_tx)
{
    // Deactive
    m_active = false;
    
    // Copy info
    m_info_dev_rx = g_strdup(dev_rx);
    m_info_mode_rx = mode_rx;
    m_info_dev_tx = g_strdup(dev_tx);
    m_info_mode_tx = mode_tx;
}

c_drv_pcap::~c_drv_pcap()
{
    // End
    if (m_active)
        end();
    
    // Free info
    g_free(m_info_dev_rx);
    g_free(m_info_dev_tx);
}

// Init and end
bool c_drv_pcap::init()
{
    // Check
    g_assert(!m_active);
    
    // Queues
    m_queue_rx = g_async_queue_new_full(c_drv_pcap::f_delete_pck);
    m_queue_tx = g_async_queue_new_full(c_drv_pcap::f_delete_pck);
    
    // Check modes
    if (m_info_mode_rx != PCAP_MODE_DEV && m_info_mode_rx != PCAP_MODE_FILE && m_info_mode_tx != PCAP_MODE_FILE) {
        g_critical("[drv] please give at least rx to tx parameters for pcap driver!");
        goto err_modes;
    }
    
    // RX
    m_rx_pcap = NULL;
    m_rx_last.tv_sec = 0;
    m_rx_last.tv_usec = 0;
    if (m_info_mode_rx == PCAP_MODE_DEV) {
        // Open device
        m_errbuf[0] = '\0';
        m_rx_pcap = pcap_open_live(m_info_dev_rx, 65535, TRUE, 2, m_errbuf);
        if (!m_rx_pcap) {
            g_critical("[drv] failed to open pcap device for reception! device=%s, error=%s", m_info_dev_rx, m_errbuf);
            goto err_pcap_rx;
        }
        m_errbuf[0] = '\0';
        if (pcap_setnonblock(m_rx_pcap, TRUE, m_errbuf) == -1) {
            g_critical("[drv] failed to set nonblocking mode for receiving device! device=%s, error=%s", m_info_dev_rx, m_errbuf);
            goto err_pcap_rx;
        }
        m_rx_link = pcap_datalink(m_rx_pcap);
    } else if (m_info_mode_rx == PCAP_MODE_FILE) {
        // Open file
        m_errbuf[0] = '\0';
        m_rx_pcap = pcap_open_offline(m_info_dev_rx, m_errbuf);
        if (!m_rx_pcap) {
            g_critical("[drv] failed to open pcap file for reception! file=%s, error=%s", m_info_dev_rx, m_errbuf);
            goto err_pcap_rx;
        }
        m_rx_link = pcap_datalink(m_rx_pcap);
    }
    if (m_rx_pcap) {
        // Link identification
        switch (m_rx_link) {
            case DLT_EN10MB: m_rx_type = LAYER_8023_PCK; break;
            case DLT_IEEE802_11: m_rx_type = LAYER_80211_PCK; break;
            case DLT_IEEE802_11_RADIO: m_rx_type = LAYER_RADIOTAP_PCK; break;
            default:
                g_critical("[drv] pcap link type not supported!");
                goto err_pcap_rx;
        }
    }
    
    // TX
    m_tx_pcap = NULL;
    m_tx_dump = NULL;
    if (m_info_mode_tx == PCAP_MODE_FILE) {
        // Open file
        m_tx_pcap = pcap_open_dead(DLT_LOOP, 65535);
        if (!m_tx_pcap) {
            g_critical("[drv] failed to open dummy pcap interface for transmission! file=%s", m_info_dev_tx);
            goto err_pcap_tx;
        }
        m_tx_dump = pcap_dump_open(m_tx_pcap, m_info_dev_tx);
        if (!m_tx_dump) {
            g_critical("[drv] failed to open packet dump for transmission! file=%s, error=%s", m_info_dev_tx, pcap_geterr(m_tx_pcap));
            goto err_pcap_tx;
        }
        m_tx_link = pcap_datalink(m_tx_pcap);
    }
    
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
        
    err_pcap_tx:
        // TX
        if (m_tx_dump)
            pcap_dump_close(m_tx_dump);
        if (m_tx_pcap)
            pcap_close(m_tx_pcap);
        
    err_pcap_rx:
        // RX
        if (m_rx_pcap)
            pcap_close(m_rx_pcap);
    
    err_modes:
        // Queues
        g_async_queue_unref(m_queue_rx);
        g_async_queue_unref(m_queue_tx);
        
        // Return
        return false;
}

void c_drv_pcap::end()
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
    
    // TX
    if (m_tx_dump)
        pcap_dump_close(m_tx_dump);
    if (m_tx_pcap)
        pcap_close(m_tx_pcap);
    
    // RX
    if (m_rx_pcap)
        pcap_close(m_rx_pcap);
    
    // Queues
    g_async_queue_unref(m_queue_rx);
    g_async_queue_unref(m_queue_tx);
    
    // Deactivate
    m_active = false;
}

// Output
void c_drv_pcap::help()
{
    // Get devices
    m_errbuf[0] = '\0';
    pcap_if_t* dev_list = NULL;
    gint ret = pcap_findalldevs(&dev_list, m_errbuf);
    if (ret != 0) {
        g_critical("[drv] failed to retrieve pcap device list! error=%s", m_errbuf);
        return;
    } else if (dev_list == NULL) {
        g_critical("[drv] no pcap devices found!");
        return;
    }
    
    // Iterate devices
    g_message("[drv] pcap devices:");
    for (pcap_if_t* dev = dev_list; dev; dev = dev->next) {
        g_message(
            "[drv] * %s: desc=%s, flags=%s",
            dev->name,
            dev->description ? dev->description : "no description",
            dev->flags & PCAP_IF_LOOPBACK ? "loopback" : "none"
        );
    }
    
    // Free devices
    pcap_freealldevs(dev_list);
}

const gchar* c_drv_pcap::name()
{
    // Check
    g_assert(m_active);
    
    // Return
    return m_info_dev_rx;
}

// Packets
st_pck_drv* c_drv_pcap::pck_rx()
{
    // Check
    g_assert(m_active);
    
    // Pop data
    return (st_pck_drv*) g_async_queue_try_pop(m_queue_rx);
}

void c_drv_pcap::pck_tx(st_pck_drv* data)
{
    // Check
    g_assert(m_active);
    
    // Push data
    g_async_queue_push(m_queue_tx, data);
}

// Loop functions
gpointer c_drv_pcap::f_loop(gpointer user)
{
    // Instance
    c_drv_pcap* ctx = (c_drv_pcap*) user;
    
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
            if (ctx->m_rx_pcap) {
                struct pcap_pkthdr* pck_hdr = NULL;
                const guint8* pck_data = NULL;
                gint ret = pcap_next_ex(ctx->m_rx_pcap, &pck_hdr, &pck_data);
                if (ret == 1 && pck_hdr->caplen > 0) {
                    // Time
                    ctx->m_rx_last.tv_sec = pck_hdr->ts.tv_sec;
                    ctx->m_rx_last.tv_usec = pck_hdr->ts.tv_usec;
                    
                    // Packet
                    st_pck_drv* pck_drv = g_new(st_pck_drv, 1);
                    pck_drv->data = g_byte_array_new();
                    pck_drv->type = ctx->m_rx_type;
                    pck_drv->driver = ctx;
                    g_byte_array_append(pck_drv->data, pck_data, pck_hdr->caplen);
                    
                    // Queue
                    g_async_queue_push(ctx->m_queue_rx, pck_drv);
                    
                    // Ok
                    ok = true;
                    
                    // Queue sleep
                    if (ctx->m_info_mode_rx == PCAP_MODE_FILE) {
                        while (g_async_queue_length(ctx->m_queue_rx) > 3)
                            g_usleep(5 * 1000);
                    }
                } else if (ret < 0) {
                    // Give error
                    if (ret == -1) {
                        g_critical("[drv] error reading packet! error=%s", pcap_geterr(ctx->m_rx_pcap));
                    } else if (ret == -2) {
                        g_critical("[drv] read all packets from savefile!");
                    } else {
                        g_critical("[drv] error reading packet! error=%s", pcap_geterr(ctx->m_rx_pcap));
                    }
                
                    // Exit loop
                    g_mutex_lock(ctx->m_thr_mutex);
                    ctx->m_thr_dead = true;
                    g_cond_signal(ctx->m_thr_cond);
                    g_mutex_unlock(ctx->m_thr_mutex);
                    return NULL;
                }
            }
            
            // Transmit packet
            st_pck_drv* pck_drv = (st_pck_drv*) g_async_queue_try_pop(ctx->m_queue_tx);
            if (pck_drv) {
                // Transmit
                if (ctx->m_tx_pcap && ctx->m_tx_dump) {
                    // Link layer header
                    guint32 layer = g_htonl(18);
                    g_byte_array_prepend(pck_drv->data, (guint8*) &layer, sizeof(layer));
                
                    // Time
                    GTimeVal time_cur;
                    if (ctx->m_info_mode_rx != PCAP_MODE_FILE) {
                        g_get_current_time(&time_cur);
                    } else {
                        time_cur.tv_sec = ctx->m_rx_last.tv_sec;
                        time_cur.tv_usec = ctx->m_rx_last.tv_usec;
                        g_time_val_add(&time_cur, 1);
                    }
                    
                    // Header
                    struct pcap_pkthdr hdr;
                    hdr.ts.tv_sec = time_cur.tv_sec;
                    hdr.ts.tv_usec = time_cur.tv_usec;
                    hdr.caplen = pck_drv->data->len;
                    hdr.len = hdr.caplen;
                    
                    // Dump
                    pcap_dump((u_char*) ctx->m_tx_dump, &hdr, pck_drv->data->data);
                }
            
                // Delete
                g_byte_array_unref(pck_drv->data);
                g_free(pck_drv);
                
                // Ok
                ok = true;
            }
        }
    }
    
    // Return
    return NULL;
}

void c_drv_pcap::f_delete_pck(gpointer data)
{
    // Free packet
    st_pck_drv* pck = (st_pck_drv*) data;
    g_byte_array_unref(pck->data);
    g_free(pck);
}

#endif

