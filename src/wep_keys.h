/*
 * Airown - WEP key generators
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

#ifndef H_WEP_KEYS
#define H_WEP_KEYS

// Int inc
#include "ao_config.h"

// Key sizes
#define WEP_KEY40_SIZE      5
#define WEP_KEY40_NUM       4
#define WEP_KEY40_STORE     (WEP_KEY40_SIZE * WEP_KEY40_NUM)
#define WEP_KEY104_SIZE     13

// Key generation
void wep_keygen40(const gchar* str, guint8* keys);
void wep_keygen104(const gchar* str, guint8* keys);

// Key printing
void wep_40keyprint(guint8* keys);
void wep_nkeyprint(guint8* key, guint nbytes);

#endif

