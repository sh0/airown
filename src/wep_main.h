/*
 * Airown - WEP encryption
 *
 * Copyright (C) 2006 toast
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

#ifndef H_WEP_MAIN
#define H_WEP_MAIN

// Int inc
#include "ao_config.h"

// Misc macros
#define IS_WEP(flags) ((flags) & 0x40)
#define WEPSMALLKEYSIZE 5
#define WEPLARGEKEYSIZE 13

/*
struct wepkey {
    guint8 key[WEPLARGEKEYSIZE];
    guint32 keylen;
    struct wepkey *next;
};
typedef struct wepkey wepkey;
*/

// Decrypt
gint32 wep_decrypt(
    const guint8* src,
    guint8* dst,
    guint32 len,
    const guint8* wepkey,
    guint32 keylen
);

// Encrypt
gint32 wep_encrypt(
    const guint8* src,
    guint8* dst,
    guint32 len,
    const guint8* wepkey,
    guint32 keylen
);

#endif

