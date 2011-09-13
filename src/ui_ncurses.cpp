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

// Int inc
#include "ao_config.h"
#include "ui_ncurses.h"

// Max log count
#define UI_MAX_LOG 120

// Constructor and destructor
c_ui_ncurses::c_ui_ncurses()
{
    // Deactive
    m_active = false;
}

c_ui_ncurses::~c_ui_ncurses()
{
    // End
    if (m_active)
        end();
}

// Init and end
bool c_ui_ncurses::init()
{
    // Check
    g_assert(!m_active);
    
    // Mutex
    m_mutex = g_mutex_new();
    if (!m_mutex)
        return false;
    
    // Log strings
    m_log_queue = g_queue_new();
    m_log_cmd = g_string_new("");
    
    // Signals
    g_atomic_int_set(&m_sig_winch, FALSE);
    
    // Init ncurses
    initscr();
    noecho();
    start_color();
    cbreak();
    refresh();
    timeout(0);
    keypad(stdscr, TRUE);
    
    // Size
    m_scr_w = m_scr_h = 0;
    getmaxyx(stdscr, m_scr_h, m_scr_w);
    if (m_scr_w <= 0 || m_scr_h <= 0)
        return false;
    
    // Windows
    f_init_win();
    
    // Redraw
    f_redraw_log();
    
    // Activate and return
    m_active = true;
    return true;
}

void c_ui_ncurses::end()
{
    // Check
    g_assert(m_active);
    
    // Windows
    f_close_win();

    // Close ncurses
    endwin();
    
    // Log strings
    while (!g_queue_is_empty(m_log_queue)) {
        gpointer data = g_queue_pop_head(m_log_queue);
        g_free(data);
    }
    g_queue_free(m_log_queue);
    g_string_free(m_log_cmd, TRUE);
    
    // Mutex
    g_mutex_free(m_mutex);
    
    // Deactivate
    m_active = false;
}

// Messages
void c_ui_ncurses::message(const gchar* msg)
{
    // Check
    g_assert(m_active);
    
    // Lock
    g_mutex_lock(m_mutex);
    
    // Push message
    guint msg_len = strlen(msg);
    guint msg_read = 0;
    while (msg_read < msg_len) {
        gchar* msgcpy = g_strdup_printf("%.*s", m_log_size_w - 2, msg + msg_read);
        g_queue_push_tail(m_log_queue, (gpointer) msgcpy);
        msg_read += m_log_size_w - 2;
    }
    
    // Max log
    while (g_queue_get_length(m_log_queue) > UI_MAX_LOG) {
        gpointer data = g_queue_pop_head(m_log_queue);
        g_free(data);
    }

    // Redraw
    f_redraw_log();
        
    // Unlock
    g_mutex_unlock(m_mutex);
}

void c_ui_ncurses::winch()
{
    // Check
    g_assert(m_active);
    
    // Signal winch
    g_atomic_int_set(&m_sig_winch, TRUE);
    
    // Size
    //scr_w = LINES;
    //scr_h = COLS;
    //resizeterm(0, 0);
    //getmaxyx(stdscr, scr_h, scr_w);
    
    // Windows
    //close_win();
    //init_win();
    
    //g_message("resize! w=%d, h=%d", scr_w, scr_h);//scr_w, scr_h);
}

gint c_ui_ncurses::poll()
{
    // Check
    g_assert(m_active);
    
    // Lock
    //g_mutex_lock(m_mutex)
    
    // Signals
    if (g_atomic_int_get(&m_sig_winch)) {
        // Deactivate signal
        g_atomic_int_set(&m_sig_winch, FALSE);
        
        // Close
        f_close_win();
        endwin();
        
        // Init
        initscr();
        noecho();
        start_color();
        cbreak();
        //refresh();
        timeout(0);
        keypad(stdscr, TRUE);
        getmaxyx(stdscr, m_scr_h, m_scr_w);
        f_init_win();
        //refresh();
        
        // Redraw
        f_redraw_log();
        
        // Return
        //g_mutex_unlock(m_mutex);
        return 0;
    }
    
    // Get key
    gint ret = 0;
    gint key = wgetch(m_log_win);

    if (!key || (key == ERR)) {
        ret = 0;
    } else if (key == KEY_BACKSPACE || key == KEY_LEFT) {
        if (m_log_cmd->len > 0) {
            g_string_truncate(m_log_cmd, m_log_cmd->len - 1);
            f_redraw_log();
        }
    } else if ((key & 0xff) == key) {
        gchar key_c = (gchar) key;
        if (g_ascii_isprint(key_c)) {
            g_string_append_c(m_log_cmd, key_c);
            f_redraw_log();
        }
    }

    // Unlock
    //g_mutex_unlock(m_mutex);
    
    // Return
    return ret;
}

// Internal functions
gboolean c_ui_ncurses::f_init_win()
{
    // Log window
    m_log_size_w = m_scr_w;
    m_log_size_h = m_scr_h; //scr_h > 20 ? 20 : scr_h;
    m_log_win = newwin(m_log_size_h, m_log_size_w, m_scr_h - m_log_size_h, 0); // h, w, y, x
    box(m_log_win, 0 , 0);
    nodelay(m_log_win, TRUE);
    keypad(m_log_win, TRUE);
    
    // Return
    return TRUE;
}

void c_ui_ncurses::f_close_win()
{
    // Log window
    delwin(m_log_win);
}

void c_ui_ncurses::f_redraw_log()
{
    // Redraw
    GList* link = g_queue_peek_tail_link(m_log_queue);
    guint count = 0;
    while (link && count < m_log_size_h - 3) {
        // Print
        gchar* msg = (gchar*) link->data;
        
        mvwhline(m_log_win, m_log_size_h - 3 - count, 1, ' ', m_log_size_w - 2);
        mvwprintw(m_log_win, m_log_size_h - 3 - count, 1, "%.*s", m_log_size_w - 2, msg);
        count++;
        
        /*
        guint msg_len = strlen(msg);
        guint msg_read = 0;
        
        while (msg_read < msg_len) {
            mvwhline(log_win, log_size_h - 3 - count, 1, ' ', log_size_w - 2);
            mvwprintw(log_win, log_size_h - 3 - count, 1, "%.*s", log_size_w - 2, msg + msg_read);
            msg_read += log_size_w - 2;
            count++;
        }
        */
        
        // Next
        link = link->prev;
    }
    
    // Input line
    mvwhline(m_log_win, m_log_size_h - 2, 1, ' ', m_log_size_w - 2);
    mvwprintw(m_log_win, m_log_size_h - 2, 1, "> %s", m_log_cmd->str);

    // Refresh
    wrefresh(m_log_win);
}

