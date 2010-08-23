/*
 * Airown - layer 4 analysis
 *
 * Copyright (C) 2010 sh0 <sh0@yutani.ee>
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

#ifndef H_PK_LAYER4
#define H_PK_LAYER4

// Int inc
#include "ao_config.h"
#include "pk_packet.h"

// Functions
void pck_tcp_read(st_ao_packet* pck);
void pck_tcp_free(st_ao_packet* pck);
void pck_udp_read(st_ao_packet* pck);
void pck_udp_free(st_ao_packet* pck);

#endif

