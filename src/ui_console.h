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

#ifndef H_UI_CONTEXT
#define H_UI_CONTEXT

// Int inc
#include "ao_config.h"
#include "ui_main.h"

// UI class
class c_ui_console : public c_ui {
    public:
        // Constructor and destructor
        c_ui_console();
        ~c_ui_console();
        
        // Init and end
        bool init();
        void end();
        
        // Messages
        void message(const gchar* msg);
        
    private:
        // Active
        bool m_active;
        
        // Mutex
        GMutex* m_mutex;
        
        // Glib log handler
        static void f_log_default(const gchar* log_domain, GLogLevelFlags log_level, const gchar* msg, gpointer user_data);
};

#endif

