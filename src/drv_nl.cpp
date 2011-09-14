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

// Int inc
#include "ao_config.h"
#include "drv_nl.h"

// Enable check
#ifdef NETLINK_FOUND

// Ext inc
/*
#include <sys/types.h>
#include <asm/types.h>
#include <netlink/genl/family.h>
#include <netlink/msg.h>
#include <netlink/attr.h>
*/

#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>

#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>

// Constructor and destructor
c_drv_netlink::c_drv_netlink(const gchar* dev)
{
    // Deactive
    m_active = false;
    
    // Copy info
    g_assert(dev);
    m_info_dev = g_strdup(dev);
}

c_drv_netlink::~c_drv_netlink()
{
    // End
    if (m_active)
        end();
    
    // Free info
    g_free(m_info_dev);
}

// Init and end
bool c_drv_netlink::init()
{
    // Check
    g_assert(!m_active);
    
    // Variables
    struct ifreq if_req;
    struct sockaddr_ll sa_ll;
    struct packet_mreq mr;
    int optval;
	socklen_t optlen;
	
	// Interface name
	m_nl_if = m_info_dev;

    // Queues
    m_queue_rx = g_async_queue_new_full(c_drv_netlink::f_delete_pck);
    m_queue_tx = g_async_queue_new_full(c_drv_netlink::f_delete_pck);

    // Netlink
	if (f_nl_connect() != true) {
		goto err_nl_connect;
	}
    
    // Socket
	m_nl_fd = socket(PF_PACKET, SOCK_RAW, g_htons(ETH_P_ALL));
	if (m_nl_fd < 0) {
		g_critical("[drv] failed to create injection socket! error=%s", strerror(errno));
		goto err_nl_fd;
	}

    // Interface index
    memset(&if_req, 0, sizeof(if_req));
    g_strlcpy(if_req.ifr_name, m_nl_if, IFNAMSIZ);
    if (ioctl(m_nl_fd, SIOCGIFINDEX, &if_req) < 0) {
        g_critical("[drv] failed to get interface index! error=%s", strerror(errno));
        goto err_nl_index;
    }

    // Bind
	memset(&sa_ll, 0, sizeof(sa_ll));
	sa_ll.sll_family = AF_PACKET;
	sa_ll.sll_protocol = g_htons(ETH_P_ALL);
	sa_ll.sll_ifindex = if_req.ifr_ifindex;
	if (bind(m_nl_fd, (struct sockaddr*) &sa_ll, sizeof(sa_ll)) != 0) {
		g_critical("[drv] failed to bind injection socket! error=%s", strerror(errno));
		goto err_nl_bind;
	}

    // Check if device is up
    optlen = sizeof(optval);
    optval = 0;
	if (getsockopt(m_nl_fd, SOL_SOCKET, SO_ERROR, &optval, &optlen) == -1) {
		g_critical("[drv] failed to get device error status! error=%s", strerror(errno));
		goto err_nl_opt;
	}
	if (optval == ENETDOWN) {
        g_critical("[drv] device seems to be down!");
        goto err_nl_opt;
	} else if (optval > 0) {
		g_critical("[drv] unknown device error! error=%s", strerror(errno));
		goto err_nl_opt;
	}

    // Priority option
	optlen = sizeof(optval);
	optval = 20;
	if (setsockopt(m_nl_fd, SOL_SOCKET, SO_PRIORITY, &optval, optlen) == -1) {
		g_critical("[drv] failed to set priority on socket! error=%s", strerror(errno));
		goto err_nl_opt;
	}
	
	// Promisc option
	memset(&mr, 0, sizeof(mr));
	mr.mr_ifindex = if_req.ifr_ifindex;
	mr.mr_type = PACKET_MR_PROMISC;
	if (setsockopt(m_nl_fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr)) == -1) {
		g_critical("[drv] failed to set interface in promisc mode! error=%s", strerror(errno));
        goto err_nl_opt;
	}
	
	// Buffer
	m_nl_recv.iov_len = 64000;
    m_nl_recv.iov_base = g_malloc(m_nl_recv.iov_len);

    // Thread
    {
        GError* err = NULL;
        m_thr_run = true;
        m_thr_dead = false;
        m_thr_mutex = g_mutex_new();
        m_thr_thread = g_thread_create(f_loop, this, TRUE, &err);
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

    // Return
    m_active = true;
    return true;
    
    // Error
    err_thread:
        // Thread
        g_mutex_free(m_thr_mutex);
        
        // Buffer
        g_free(m_nl_recv.iov_base);
        
    err_nl_opt:
    err_nl_bind:
    err_nl_index:
        // Socket
        close(m_nl_fd);
    
    err_nl_fd:
        // Disconnect
        f_nl_disconnect();
        
    err_nl_connect:
        // Queues
        g_async_queue_unref(m_queue_rx);
        g_async_queue_unref(m_queue_tx);
    
        // Return
        return false;
}

void c_drv_netlink::end()
{
    // Check
    g_assert(m_active);
    
    // Thread
    g_mutex_lock(m_thr_mutex);
    m_thr_run = false;
    g_mutex_unlock(m_thr_mutex);
    g_thread_join(m_thr_thread);
    g_mutex_free(m_thr_mutex);
    
    // Buffer
    g_free(m_nl_recv.iov_base);
    
    // Socket
    close(m_nl_fd);
    
    // Disconnect
    f_nl_disconnect();
    
    // Queues
    g_async_queue_unref(m_queue_rx);
    g_async_queue_unref(m_queue_tx);
    
    // Deactive
    m_active = false;
}

// Output
void c_drv_netlink::help()
{
    // Message
    g_message("Netlink devices:");
}

const gchar* c_drv_netlink::name()
{
    // Check
    g_assert(m_active);

    // Return
    return m_nl_if;
}

// Packets
st_pck_drv* c_drv_netlink::pck_rx()
{
    // Check
    g_assert(m_active);
    
    // Pop data
    return (st_pck_drv*) g_async_queue_try_pop(m_queue_rx);
}

void c_drv_netlink::pck_tx(st_pck_drv* data)
{
    // Check
    g_assert(m_active);
    
    // Push data
    g_async_queue_push(m_queue_tx, data);
}

// Loop functions
gpointer c_drv_netlink::f_loop(gpointer user)
{
    // Instance
    c_drv_netlink* ctx = (c_drv_netlink*) user;
    
    // Packet loop
    while (true) {
        // Exit check
        g_mutex_lock(ctx->m_thr_mutex);
        if (!ctx->m_thr_run) {
            ctx->m_thr_dead = true;
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
            //guint8 rx_ctmp[128];
            struct msghdr rx_msg;
            rx_msg.msg_name = NULL;
            rx_msg.msg_namelen = 0;
            rx_msg.msg_iov = &ctx->m_nl_recv;
            rx_msg.msg_iovlen = 1;
            rx_msg.msg_control = NULL; //&rx_ctmp;
            rx_msg.msg_controllen = 0; //sizeof(rx_ctmp);
            rx_msg.msg_flags = 0;
            ssize_t rx_size = recvmsg(ctx->m_nl_fd, &rx_msg, MSG_DONTWAIT);
            if (rx_size > 0) {
                // Layer
                /*
                struct cmsghdr* rx_cmsg = CMSG_FIRSTHDR(&rx_msg);
                if (rx_cmsg) {
                    g_message("[drv] got packet! level=%d", rx_cmsg->cmsg_level);
                }
                */
                
                // Packet
                st_pck_drv* pck_drv = g_new(st_pck_drv, 1);
                pck_drv->data = g_byte_array_new();
                pck_drv->type = LAYER_RADIOTAP_PCK;
                pck_drv->driver = ctx;
                
                // Data
                g_byte_array_append(pck_drv->data, (guint8*) rx_msg.msg_iov[0].iov_base, rx_size);
                
                // Queue
                g_async_queue_push(ctx->m_queue_rx, pck_drv);
                
                // Ok
                ok = true;
            } else if (errno != EAGAIN) {
                // Error
                g_critical("[drv] error reading packet! error=%s", strerror(errno));
                
                // Exit loop
                g_mutex_lock(ctx->m_thr_mutex);
                ctx->m_thr_dead = true;
                g_mutex_unlock(ctx->m_thr_mutex);
                return NULL;
            }
            
            // Transmit packet
            st_pck_drv* pck_drv = (st_pck_drv*) g_async_queue_try_pop(ctx->m_queue_tx);
            if (pck_drv) {
                // Message
                struct iovec tx_iov;
                tx_iov.iov_base = pck_drv->data->data;
                tx_iov.iov_len = pck_drv->data->len;
                struct msghdr tx_msg;
                tx_msg.msg_name = NULL;
                tx_msg.msg_namelen = 0;
                tx_msg.msg_iovlen = 1;
                tx_msg.msg_iov = &tx_iov;
                tx_msg.msg_control = NULL;
                tx_msg.msg_controllen = 0;
                tx_msg.msg_flags = 0;
                
                // Send
                ssize_t tx_size = sendmsg(ctx->m_nl_fd, &tx_msg, 0);
                if (tx_size < 0) {
                    // Error
                    g_critical("[drv] error sending packet! error=%s", strerror(errno));
                    
                    // Exit loop
                    g_mutex_lock(ctx->m_thr_mutex);
                    ctx->m_thr_dead = true;
                    g_mutex_unlock(ctx->m_thr_mutex);
                    return NULL;
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

void c_drv_netlink::f_delete_pck(gpointer data)
{
    // Free packet
    st_pck_drv* pck = (st_pck_drv*) data;
    g_byte_array_unref(pck->data);
    g_free(pck);
}

// Netlink functions
bool c_drv_netlink::f_nl_connect()
{
    // Netlink handle
	if ((m_nl_handle = nl_handle_alloc()) == NULL) {
		g_critical("[drv] failed to allocate nl_handle!");
		goto err_handle;
	}

	if (genl_connect(m_nl_handle)) {
		g_critical("[drv] failed to connect to generic netlink!");
		goto err_connect;
	}

    m_nl_cache = genl_ctrl_alloc_cache(m_nl_handle);
	if (m_nl_cache == NULL) {
		g_critical("[drv] failed to allocate generic netlink cache!");
		goto err_cache;
	}

	if ((m_nl_family = genl_ctrl_search_by_name(m_nl_cache, "nl80211")) == NULL) {
		g_critical("[drv] failed to find nl80211 controls, kernel may be too old!");
		goto err_family;
	}

    // Return
	return true;
	
	// Error
	err_family:
	    // Cache
	    nl_cache_free(m_nl_cache);
	    
	err_cache:
	err_connect:
	    // Handle
	    nl_handle_destroy(m_nl_handle);
	    
	err_handle:
	    // Return
	    return false;
}

void c_drv_netlink::f_nl_disconnect()
{
    // Netlink handle
    nl_handle_destroy(m_nl_handle);
}

#endif

