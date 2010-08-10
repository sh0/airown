/*
 * Airown - payload
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
#include "ao_main.h"
#include "ao_packet.h"
#include "ao_payload.h"
#include "ao_util.h"

// Functions
gboolean ao_payload_init()
{
    // Open
    if ((ao_inst.cmd_payload == NULL) || (strlen(ao_inst.cmd_payload) <= 0)) {
        g_print("[pay] no payload config!\n");
        return TRUE;
    }
    GError* err = NULL;
    GKeyFile* key = g_key_file_new();
    if (key == NULL) {
        g_print("[pay] error creating glib key file handler!\n");
        return FALSE;
    }
    if (g_key_file_load_from_file(key, ao_inst.cmd_payload, G_KEY_FILE_NONE, &err) == FALSE) {
        if (err != NULL) {
            g_print("[pay] error opening payload configuration! error=%s\n", err->message);
            g_clear_error(&err);
        } else {
            g_print("[pay] error opening payload configuration!\n");
        }
        return FALSE;
    }
    
    // Return
    return TRUE;
}

void ao_payload_end()
{

}

/*
FILE* fs = fopen("/root/tool-wifi/airpwn/content/goatse-image", "rb");
fseek(fs, 0, SEEK_END);
ao_payload_size = ftell(fs);
fseek(fs, 0, SEEK_SET);
ao_payload_data = (uint8_t*) malloc(ao_payload_size);
fread(ao_payload_data, ao_payload_size, 1, fs);
fclose(fs);
*/

