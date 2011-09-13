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

// Constructor and destructor
c_drv_netlink::c_drv_netlink(const gchar* dev)
{

}

c_drv_netlink::~c_drv_netlink()
{

}

// Init and end
bool c_drv_netlink::init()
{
    return false;
}

void c_drv_netlink::end()
{

}

// Output
void c_drv_netlink::help()
{

}

const gchar* c_drv_netlink::name()
{
    return NULL;
}

// Packets
st_pck_drv* c_drv_netlink::pck_rx()
{
    return NULL;
}

void c_drv_netlink::pck_tx(st_pck_drv* data)
{

}

#endif

