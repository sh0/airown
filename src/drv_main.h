/*
 * Airown - Driver
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

#ifndef H_DRV_MAIN
#define H_DRV_MAIN

// Int inc
#include "ao_config.h"

// Declarations
class c_drv;

// Packet transfer struct
typedef struct {
    GByteArray* data;
    guint type;
    c_drv* driver;
} st_pck_drv;

// Driver class
class c_drv {
    public:
        // Destructor
        virtual ~c_drv() { }
        
        // Init and end
        virtual bool init() = 0;
        virtual void end() = 0;
        
        // Output
        virtual void help() = 0;
        virtual const gchar* name() = 0;
        
        // Packets
        virtual st_pck_drv* pck_rx() = 0;
        virtual void pck_tx(st_pck_drv* data) = 0;
};

#endif

