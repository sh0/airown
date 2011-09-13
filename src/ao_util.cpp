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

// Int inc
#include "ao_config.h"
#include "ao_util.h"

// Hex dump
void c_util::hex_log(const gchar* prefix, guint8* data, guint size)
{
    // Check
    g_assert(data);
    if (!size)
        return;
    
    // Print
    GString* str = f_hex_v(data, size);
    g_message("%s size=%u\n%s", prefix, size, str->str);
    g_string_free(str, TRUE);
}

void c_util::hex_log_c(const gchar* prefix, guint8* data, guint size)
{
    // Check
    g_assert(data);
    if (!size)
        return;
    
    // Print
    GString* str = f_hex_c(data, size);
    g_message("%s size=%u\n%s", prefix, size, str->str);
    g_string_free(str, TRUE);
}

void c_util::hex_file(const gchar* fn, guint8* data, guint size)
{
    // Check
    g_assert(data);
    if (!size)
        return;
    
    // Print
    GString* str = f_hex_v(data, size);
    GError* err = NULL;
    if (g_file_set_contents(fn, str->str, str->len, &err)) {
        g_message("[ao] hex dumped to file! size=%u, file=%s", size, fn);
    } else {
        if (err) {
            g_warning("[ao] failed to dump hex to file! size=%u, file=%s, error=%s", size, fn, err->message);
            g_clear_error(&err);
        } else {
            g_warning("[ao] failed to dump hex to file! size=%u, file=%s, error=unknown", size, fn);
        }
    }
    g_string_free(str, TRUE);
}

void c_util::hex_file_c(const gchar* fn, guint8* data, guint size)
{
    // Check
    g_assert(data);
    if (!size)
        return;
    
    // Print
    GString* str = f_hex_c(data, size);
    GError* err = NULL;
    if (g_file_set_contents(fn, str->str, str->len, &err)) {
        g_message("[ao] hex dumped to file! size=%u, file=%s", size, fn);
    } else {
        if (err) {
            g_warning("[ao] failed to dump hex to file! size=%u, file=%s, error=%s", size, fn, err->message);
            g_clear_error(&err);
        } else {
            g_warning("[ao] failed to dump hex to file! size=%u, file=%s, error=unknown", size, fn);
        }
    }
    g_string_free(str, TRUE);
}

void c_util::hex_file_raw(const gchar* fn, guint8* data, guint size)
{
    // Check
    g_assert(data);
    if (!size)
        return;
    
    // Print
    GError* err = NULL;
    if (g_file_set_contents(fn, (const gchar*) data, size, &err)) {
        g_warning("[ao] hex dumped to file! size=%u, file=%s", size, fn);
    } else {
        if (err) {
            g_warning("[ao] failed to dump hex to file! size=%u, file=%s, error=%s", size, fn, err->message);
            g_clear_error(&err);
        } else {
            g_warning("[ao] failed to dump hex to file! size=%u, file=%s, error=unknown", size, fn);
        }
    }
}

// Compare addresses
gboolean c_util::cmp_ipv4(struct in_addr* a, struct in_addr* b)
{
    if (*((guint32*)a) != *((guint32*)b))
        return FALSE;
    return TRUE;
}

gboolean c_util::cmp_ipv6(struct libnet_in6_addr* a, struct libnet_in6_addr* b)
{
    gint i;
    for (i=0; i<8; i++) {
        if (a->__u6_addr.__u6_addr16[i] != b->__u6_addr.__u6_addr16[i])
            return FALSE;
    }
    return TRUE;
}

gboolean c_util::cmp_ipv4_mask(struct in_addr* a, struct in_addr* b, struct in_addr* mask)
{
    guint32 am = *((guint32*)a) & *((guint32*)mask);
    guint32 bm = *((guint32*)b) & *((guint32*)mask);
    if (am != bm)
        return FALSE;
    return TRUE;
}

gboolean c_util::cmp_ipv6_mask(struct libnet_in6_addr* a, struct libnet_in6_addr* b, struct libnet_in6_addr* mask)
{
    gint i;
    for (i=0; i<8; i++) {
        if ((a->__u6_addr.__u6_addr16[i] & mask->__u6_addr.__u6_addr16[i]) !=
            (b->__u6_addr.__u6_addr16[i] & mask->__u6_addr.__u6_addr16[i]))
            return FALSE;
    }
    return TRUE;
}

// Copy addresses
void c_util::cpy_ipv4(struct in_addr* dst, struct in_addr* src)
{
    g_memmove(dst, src, sizeof(struct in_addr));
}

void c_util::cpy_ipv6(struct libnet_in6_addr* dst, struct libnet_in6_addr* src)
{
    g_memmove(dst, src, sizeof(struct libnet_in6_addr));
}

// Hex dump
GString* c_util::f_hex_v(guint8* data, guint size)
{
    // Check
    g_assert(data && size);
    
    // Buffer
    GString* str = g_string_new("");

    // Loop
	guint8* data_all_cur = data;
	guint8* data_all_end = data + size;
	while (data_all_cur < data_all_end) {
        // Pointers
        guint8* data_hex_cur = data_all_cur;
        guint8* data_hex_end = MIN(data_all_cur + 16, data_all_end);
        guint8* data_str_cur = data_hex_cur;
        guint8* data_str_end = data_hex_end;
        gint data_over = MAX(0, (data_all_cur + 16) - data_all_end);

		// Hex
		g_string_append(str, "| ");
		while (data_hex_cur < data_hex_end)
			g_string_append_printf(str, "%02x ", *(data_hex_cur++));
		for (gint i = 0; i < data_over; i++)
			g_string_append(str, "   ");

		// String
		g_string_append(str, "| ");
		while (data_str_cur < data_str_end) {
			gchar ch = *(data_str_cur++);
			if ((ch >= 32) && (ch <= 126))
				g_string_append_printf(str, "%c", ch);
			else
				g_string_append(str, ".");
		}
		for (gint i = 0; i < data_over; i++)
			g_string_append(str, " ");
		g_string_append(str, " |");

		// Next
		data_all_cur = data_hex_end;
		if (data_all_cur < data_all_end)
		    g_string_append(str, "\n");
	}
	
	// Return
	return str;
}

GString* c_util::f_hex_c(guint8* data, guint size)
{
    // Check
    g_assert(data && size);
    
    // Buffer
    GString* str = g_string_new("guint8 data[] = {\n");

    // Loop
	guint8* data_cur = data;
	guint8* data_end = data + size;
	while (data_cur < data_end) {
	    // Print
	    g_string_append(str, "    ");
	    guint num = MIN(data_end - data_cur, 16);
	    for (guint i=0; i<num - 1; i++)
	        g_string_printf(str, "0x%02x, ", *(data_cur++));
	    if (data_end - data_cur == 1)
    	    g_string_printf(str, "0x%02x\n", *(data_cur++));
	    else
	        g_string_printf(str, "0x%02x,\n", *(data_cur++));
	}
	
	// Ending
	g_string_append(str, "};");
	
	// Return
	return str;
}

