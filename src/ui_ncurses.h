/*
 * Airown - User interface - Ncurses
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

#ifndef H_UI_NCURSES
#define H_UI_NCURSES

// Int inc
#include "ao_config.h"
#include "ui_main.h"

// Ext inc
#include <ncurses.h>

// UI class
class c_ui_ncurses : public c_ui {
    public:
        // Constructor and destructor
        c_ui_ncurses();
        ~c_ui_ncurses();
        
        // Init and end
        bool init();
        void end();
        
        // Messages
        void message(const gchar* msg);
        
        // Winch and poll
        void winch();
        gint poll();
        
    private:
        // Active
        bool m_active;
        
        // Mutex
        GMutex* m_mutex;
        
        // Signals
        gint m_sig_winch;

        // Screen
        gint m_scr_w;
        gint m_scr_h;

        // Log window
        WINDOW* m_log_win;
        guint32 m_log_size_w;
        guint32 m_log_size_h;
        GQueue* m_log_queue;
        GString* m_log_cmd;

        // Declarations
        gboolean f_init_win();
        void f_close_win();
        void f_redraw_log();
};

#endif

