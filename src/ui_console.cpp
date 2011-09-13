/*
 * Airown - User interface - Console
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
#include "ui_console.h"

// Constructor and destructor
c_ui_console::c_ui_console()
{
    // Deactive
    m_active = false;
}

c_ui_console::~c_ui_console()
{
    // End
    if (m_active)
        end();
}

// Init and end
bool c_ui_console::init()
{
    // Check
    g_assert(!m_active);
    
    // Mutex
    m_mutex = g_mutex_new();
    if (!m_mutex)
        return false;
    
    // Log handler
    g_log_set_default_handler(c_ui_console::f_log_default, this);
    
    // Activate and return
    m_active = true;
    return true;
}

void c_ui_console::end()
{
    // Check
    g_assert(m_active);
    
    // Mutex
    g_mutex_free(m_mutex);
    
    // Deactivate
    m_active = false;
}

// Messages
void c_ui_console::message(const gchar* msg)
{
    // Check
    g_assert(m_active);
    
    // Lock, write, unlock
    g_mutex_lock(m_mutex);
    g_print("%s\n", msg);
    g_mutex_unlock(m_mutex);
}

// Glib log handler
void c_ui_console::f_log_default(const gchar* log_domain, GLogLevelFlags log_level, const gchar* msg, gpointer user_data)
{
    // Instance
    c_ui_console* ui = (c_ui_console*) user_data;
    
    // Console
    ui->message(msg);
}

