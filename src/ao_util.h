/*
 * Airown - Utility functions
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

#ifndef H_AO_UTIL
#define H_AO_UTIL

// Int inc
#include "ao_config.h"

// Utility class
class c_util {
    public:
        // Hex dump
        static void hex_log(const gchar* prefix, guint8* data, guint size);
        static void hex_log_c(const gchar* prefix, guint8* data, guint size);
        static void hex_file(const gchar* fn, guint8* data, guint size);
        static void hex_file_c(const gchar* fn, guint8* data, guint size);
        static void hex_file_raw(const gchar* fn, guint8* data, guint size);

        // Compare addresses
        static gboolean cmp_ipv4(struct in_addr* a, struct in_addr* b);
        static gboolean cmp_ipv6(struct libnet_in6_addr* a, struct libnet_in6_addr* b);
        static gboolean cmp_ipv4_mask(struct in_addr* a, struct in_addr* b, struct in_addr* mask);
        static gboolean cmp_ipv6_mask(struct libnet_in6_addr* a, struct libnet_in6_addr* b, struct libnet_in6_addr* mask);

        // Copy addresses
        static void cpy_ipv4(struct in_addr* dst, struct in_addr* src);
        static void cpy_ipv6(struct libnet_in6_addr* dst, struct libnet_in6_addr* src);

    private:
        // Hex dump
        static GString* f_hex_v(guint8* data, guint size);
        static GString* f_hex_c(guint8* data, guint size);
};

#endif

