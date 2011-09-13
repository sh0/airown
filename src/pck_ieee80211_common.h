/*
 * IEEE 802.11 Common routines
 *
 * Copyright (c) 2002-2009, Jouni Malinen <j@w1.fi>
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

#ifndef H_PCK_IEEE80211_COMMON
#define H_PCK_IEEE80211_COMMON

// Parsed Information Elements
struct ieee802_11_elems {
	const guint8 *ssid;
	const guint8 *supp_rates;
	const guint8 *fh_params;
	const guint8 *ds_params;
	const guint8 *cf_params;
	const guint8 *tim;
	const guint8 *ibss_params;
	const guint8 *challenge;
	const guint8 *erp_info;
	const guint8 *ext_supp_rates;
	const guint8 *wpa_ie;
	const guint8 *rsn_ie;
	const guint8 *wmm; // WMM Information or Parameter Element
	const guint8 *wmm_tspec;
	const guint8 *wps_ie;
	const guint8 *power_cap;
	const guint8 *supp_channels;
	const guint8 *mdie;
	const guint8 *ftie;
	const guint8 *timeout_int;
	const guint8 *ht_capabilities;
	const guint8 *ht_operation;
	const guint8 *vendor_ht_cap;

	guint8 ssid_len;
	guint8 supp_rates_len;
	guint8 fh_params_len;
	guint8 ds_params_len;
	guint8 cf_params_len;
	guint8 tim_len;
	guint8 ibss_params_len;
	guint8 challenge_len;
	guint8 erp_info_len;
	guint8 ext_supp_rates_len;
	guint8 wpa_ie_len;
	guint8 rsn_ie_len;
	guint8 wmm_len; // 7 = WMM Information; 24 = WMM Parameter
	guint8 wmm_tspec_len;
	guint8 wps_ie_len;
	guint8 power_cap_len;
	guint8 supp_channels_len;
	guint8 mdie_len;
	guint8 ftie_len;
	guint8 timeout_int_len;
	guint8 ht_capabilities_len;
	guint8 ht_operation_len;
	guint8 vendor_ht_cap_len;
};

#if 0

typedef enum { ParseOK = 0, ParseUnknown = 1, ParseFailed = -1 } ParseRes;

ParseRes ieee802_11_parse_elems(const guint8 *start, gsize len, struct ieee802_11_elems *elems, gint show_errors);
int ieee802_11_ie_count(const guint8* ies, gsize ies_len);
struct wpabuf* ieee802_11_vendor_ie_concat(const guint8* ies, gsize ies_len, guint32 oui_type);

#endif

#endif

