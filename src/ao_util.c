/*
 * Airown - utility functions
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

// Int inc
#include "ao_config.h"
#include "ao_util.h"

// Hex dump
void dumphex(guint8* data, guint32 len)
{
	uint32_t i;

	uint32_t done = 0;
	while (len > done) {

		// Hex
		uint32_t cur = 0;
		printf("| ");
		while ((cur < 16) && (len >= done + cur)) {
			printf("%02x ", data[done + cur]);
			cur++;
		}
		for (i = 0; i < (16-cur); i++)
			printf("   ");

		// String
		printf("| ");
		cur = 0;
		while ((cur < 16) && (len >= done + cur)) {
			char ch = data[done + cur];			
			if ((ch >= 32) && (ch <= 126))
				printf("%c", data[done + cur]);
			else
				printf(".");			
			cur++;
		}
		for (i = 0; i < (16-cur); i++)
			printf(" ");
		printf(" |\n");

		// Next
		done += cur;
	}
}

// Compare addresses
gboolean cmp_ipv4(struct in_addr* a, struct in_addr* b)
{
    if (*((guint32*)a) != *((guint32*)b))
        return FALSE;
    return TRUE;
}

gboolean cmp_ipv6(struct libnet_in6_addr* a, struct libnet_in6_addr* b)
{
    gint i;
    for (i=0; i<8; i++) {
        if (a->__u6_addr.__u6_addr16[i] != b->__u6_addr.__u6_addr16[i])
            return FALSE;
    }
    return TRUE;
}

gboolean cmp_ipv4_mask(struct in_addr* a, struct in_addr* b, struct in_addr* mask)
{
    guint32 am = *((guint32*)a) & *((guint32*)mask);
    guint32 bm = *((guint32*)b) & *((guint32*)mask);
    if (am != bm)
        return FALSE;
    return TRUE;
}

gboolean cmp_ipv6_mask(struct libnet_in6_addr* a,
                       struct libnet_in6_addr* b,
                       struct libnet_in6_addr* mask)
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
void cpy_ipv4(struct in_addr* dst, struct in_addr* src)
{
    g_memmove(dst, src, sizeof(struct in_addr));
}

void cpy_ipv6(struct libnet_in6_addr* dst, struct libnet_in6_addr* src)
{
    g_memmove(dst, src, sizeof(struct libnet_in6_addr));
}

