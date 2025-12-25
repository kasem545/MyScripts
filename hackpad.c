/*  HackPad - A simple note-taking application 
    created for penetration testers.
    can be compiled with: gcc HackPad.c -lncurses -o HackPad
    Copyright (C) 2025  <Kasem Shibli> <kasem545@proton.me>

    Compile:
      gcc HackPad.c -lncurses -o HackPad

    Usage:
      ./HackPad [file.md]

    Keys (main):
      ?         Help (press ? or ESC to close help)
      h/l       Focus Sections / Entries
      j/k       Move
      N         New section (same level, inserted after selected section subtree)
      B         New sub-section (child, inserted after selected section subtree)
      D         Delete section/entry (depending focus)
      O         Collapse/expand section or entry (depending focus)

      A         Add entry (top-level, inserted after selected entry subtree)
      b         Add sub-entry (child of selected entry, inserted after selected entry subtree)
      E         Edit entry text
      T         Edit tags
      P         Set priority
      C         Set color (entry when focus entries, section when focus sections)
      X         Toggle complete
      *         Pin/unpin entry
      F         Filter by tag
      V         View mode (all/tag/priority/completed/incomplete)
      R         Reset filters
      M         Toggle timestamps
      Y         Export current section to markdown
      S         Save
      W         Save as
      Q         Quit

*/

// Plese Note: If there is segmente fault when running, try increasing stack size limit in terminal with `ulimit -s unlimited`

#define _XOPEN_SOURCE 700
#include <ncurses.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <time.h>
#include <strings.h>

/* ---------------- Limits ---------------- */

#define MAX_SECTIONS  96
#define MAX_ENTRIES   8192
#define MAX_TEXT      1024
#define MAX_NAME      128
#define MAX_TAGS      8
#define MAX_TAG_LEN   32

/* ---------------- Portable strcasestr fallback ---------------- */

static char *hackpad_strcasestr(const char *haystack, const char *needle) {
    if (!haystack || !needle) return NULL;
    if (!*needle) return (char *)haystack;

    size_t nlen = strlen(needle);
    for (const char *p = haystack; *p; p++) {
        if (strncasecmp(p, needle, nlen) == 0) return (char *)p;
    }
    return NULL;
}

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
  #ifndef strcasestr
    #define strcasestr hackpad_strcasestr
  #endif
#elif !defined(_GNU_SOURCE)
  #ifndef strcasestr
    #define strcasestr hackpad_strcasestr
  #endif
#endif

/* ---------------- Types ---------------- */

typedef enum {
    PRIORITY_NONE,
    PRIORITY_LOW,
    PRIORITY_MEDIUM,
    PRIORITY_HIGH,
    PRIORITY_CRITICAL
} Priority;

/* IMPORTANT: Do NOT name these COLOR_* (ncurses macros will explode your build). */
typedef enum {
    HP_COLOR_NONE = 0,
    HP_COLOR_RED,
    HP_COLOR_GREEN,
    HP_COLOR_YELLOW,
    HP_COLOR_ORANGE,   /* simulated via YELLOW+BOLD */
    HP_COLOR_MAGENTA,
    HP_COLOR_CYAN,
    HP_COLOR_WHITE
} UiColor;

typedef enum {
    FOCUS_SECTIONS,
    FOCUS_ENTRIES
} Focus;

typedef enum {
    VIEW_ALL,
    VIEW_TAGGED,
    VIEW_PRIORITY,
    VIEW_COMPLETED,
    VIEW_INCOMPLETE
} ViewFilter;

typedef struct {
    int id;
    int parent_id;
    int depth;
    int collapsed;
    UiColor color;
    char name[MAX_NAME];
} Section;

typedef struct {
    int id;
    int section_id;
    int parent_id;
    int depth;
    int collapsed;

    char text[MAX_TEXT];
    char tags[MAX_TAGS][MAX_TAG_LEN];
    int tag_count;
    Priority priority;
    UiColor color;
    time_t created;
    time_t modified;
    int completed;
    int pinned;
} Entry;

typedef struct {
    Section sections[MAX_SECTIONS];
    int section_count;

    Entry entries[MAX_ENTRIES];
    int entry_count;

    int current_section_id;
    int selected_entry_id;

    Focus focus;

    char filename[256];
    time_t created_time;

    ViewFilter filter;
    char filter_tag[MAX_TAG_LEN];
    Priority filter_priority;

    int show_timestamps;
    int show_help;

    int next_section_id;
    int next_entry_id;

    /* UI windows (rebuilt on resize) */
    int sw;
    WINDOW *secw, *entw;
    WINDOW *secf, *entf;
    WINDOW *helpw;
} HackPad;

/* ---------------- Templates ---------------- */

static const char *host_template    = "IP: 10.0.0.1 | Hostname: | OS: | Ports: ";
static const char *cred_template    = "Username: | Password: | Hash: | Service: ";
static const char *exploit_template = "CVE: | Target: | Payload: | Success: ";
static const char *vuln_template    = "Severity: | Service: | Description: | Remediation: ";

/* ---------------- UI / Theme ---------------- */

enum {
    CP_HEADER = 1,
    CP_STATUS,
    CP_DIM,
    CP_ERR,
    CP_TAG,
    CP_PMED,
    CP_PLOW,
    CP_PIN,
    CP_RED,
    CP_GREEN,
    CP_YELLOW,
    CP_ORANGE,
    CP_MAGENTA,
    CP_CYAN,
    CP_WHITE
};

static void ui_init(void) {
    initscr();
    cbreak();
    noecho();
    keypad(stdscr, TRUE);
    set_escdelay(25);
    curs_set(0);

    if (has_colors()) {
        start_color();
        use_default_colors();

        init_pair(CP_HEADER,  COLOR_CYAN,    -1);
        init_pair(CP_STATUS,  COLOR_YELLOW,  -1);
        init_pair(CP_DIM,     COLOR_BLACK,   -1);
        init_pair(CP_ERR,     COLOR_RED,     -1);
        init_pair(CP_TAG,     COLOR_MAGENTA, -1);
        init_pair(CP_PMED,    COLOR_MAGENTA, -1); /* medium priority -> purple-ish */
        init_pair(CP_PLOW,    COLOR_WHITE,   -1);
        init_pair(CP_PIN,     COLOR_GREEN,   -1);

        init_pair(CP_RED,     COLOR_RED,     -1);
        init_pair(CP_GREEN,   COLOR_GREEN,   -1);
        init_pair(CP_YELLOW,  COLOR_YELLOW,  -1);
        init_pair(CP_ORANGE,  COLOR_YELLOW,  -1); /* simulate orange with bold */
        init_pair(CP_MAGENTA, COLOR_MAGENTA, -1);
        init_pair(CP_CYAN,    COLOR_CYAN,    -1);
        init_pair(CP_WHITE,   COLOR_WHITE,   -1);
    }
    refresh();
}

static void ui_shutdown(void) { endwin(); }

static void status_msg(const char *msg) {
    if (has_colors()) attron(COLOR_PAIR(CP_STATUS));
    mvprintw(LINES - 1, 0, "%s", msg);
    clrtoeol();
    if (has_colors()) attroff(COLOR_PAIR(CP_STATUS));
    refresh();
}

static const char* priority_str(Priority p) {
    switch(p) {
        case PRIORITY_CRITICAL: return "P0";
        case PRIORITY_HIGH:     return "P1";
        case PRIORITY_MEDIUM:   return "P2";
        case PRIORITY_LOW:      return "P3";
        default:                return "";
    }
}

static int priority_color_pair(Priority p) {
    switch(p) {
        case PRIORITY_CRITICAL:
        case PRIORITY_HIGH:     return CP_ERR;
        case PRIORITY_MEDIUM:   return CP_PMED;
        case PRIORITY_LOW:      return CP_PLOW;
        default:                return 0;
    }
}

static const char* color_str(UiColor c) {
    switch(c) {
        case HP_COLOR_RED:     return "RED";
        case HP_COLOR_GREEN:   return "GREEN";
        case HP_COLOR_YELLOW:  return "YELLOW";
        case HP_COLOR_ORANGE:  return "ORANGE";
        case HP_COLOR_MAGENTA: return "MAGENTA";
        case HP_COLOR_CYAN:    return "CYAN";
        case HP_COLOR_WHITE:   return "WHITE";
        default:               return "";
    }
}

static int color_pair(UiColor c) {
    switch(c) {
        case HP_COLOR_RED:     return CP_RED;
        case HP_COLOR_GREEN:   return CP_GREEN;
        case HP_COLOR_YELLOW:  return CP_YELLOW;
        case HP_COLOR_ORANGE:  return CP_ORANGE;
        case HP_COLOR_MAGENTA: return CP_MAGENTA;
        case HP_COLOR_CYAN:    return CP_CYAN;
        case HP_COLOR_WHITE:   return CP_WHITE;
        default:               return 0;
    }
}

static int color_is_orange(UiColor c) { return c == HP_COLOR_ORANGE; }

/* ---------------- Helpers ---------------- */

static void trim_trailing_spaces(char *s) {
    if (!s) return;
    size_t n = strlen(s);
    while (n > 0 && isspace((unsigned char)s[n - 1])) { s[n - 1] = '\0'; n--; }
}

static int count_leading_spaces(const char *s) {
    int c = 0;
    while (*s && *s == ' ') { c++; s++; }
    return c;
}

static int count_heading_level(const char *s) {
    int c = 0;
    while (*s == '#') { c++; s++; }
    return c;
}

static int find_section_index_by_id(HackPad *nb, int id) {
    for (int i = 0; i < nb->section_count; i++)
        if (nb->sections[i].id == id) return i;
    return -1;
}

static int find_entry_index_by_id(HackPad *nb, int id) {
    for (int i = 0; i < nb->entry_count; i++)
        if (nb->entries[i].id == id) return i;
    return -1;
}

/* Entry filter only (search removed by request) */
static int entry_matches_filter(HackPad *nb, Entry *e) {
    if (!nb || !e) return 0;

    switch (nb->filter) {
        case VIEW_TAGGED:
            if (nb->filter_tag[0]) {
                int found = 0;
                for (int i = 0; i < e->tag_count; i++) {
                    if (strcasecmp(e->tags[i], nb->filter_tag) == 0) { found = 1; break; }
                }
                if (!found) return 0;
            } else {
                if (e->tag_count == 0) return 0;
            }
            break;
        case VIEW_PRIORITY:
            if (e->priority != nb->filter_priority) return 0;
            break;
        case VIEW_COMPLETED:
            if (!e->completed) return 0;
            break;
        case VIEW_INCOMPLETE:
            if (e->completed) return 0;
            break;
        case VIEW_ALL:
        default:
            break;
    }
    return 1;
}

/* ---------------- Line editor / dialogs ---------------- */

static int line_editor(const char *title, char *buf, int max_len) {
    int h = 7;
    int w = COLS - 6;
    if (w < 20) w = 20;

    int y = (LINES - h) / 2; if (y < 0) y = 0;
    int x = 3; if (x < 0) x = 0;

    WINDOW *win = newwin(h, w, y, x);
    box(win, 0, 0);
    keypad(win, TRUE);
    curs_set(1);

    int len = (int)strlen(buf);
    if (len >= max_len) { buf[max_len - 1] = '\0'; len = (int)strlen(buf); }
    int cur = len;

    int ch;
    int view = 0;
    int field_w = w - 4;

    while (1) {
        werase(win);
        box(win, 0, 0);
        mvwprintw(win, 0, 2, " %s ", title);
        mvwprintw(win, 4, 2, "Enter:Save  ESC:Cancel  ^U:Clear");

        if (cur < view) view = cur;
        if (cur > view + field_w - 1) view = cur - (field_w - 1);
        if (view < 0) view = 0;

        char slice[MAX_TEXT];
        memset(slice, 0, sizeof(slice));
        strncpy(slice, buf + view, (size_t)field_w);
        slice[field_w] = '\0';
        mvwprintw(win, 2, 2, "%s", slice);

        int cursor_x = 2 + (cur - view);
        if (cursor_x < 2) cursor_x = 2;
        if (cursor_x > w - 3) cursor_x = w - 3;
        wmove(win, 2, cursor_x);

        wrefresh(win);
        ch = wgetch(win);

        if (ch == 27) { delwin(win); curs_set(0); return 0; }
        if (ch == '\n') { delwin(win); curs_set(0); return 1; }

        if (ch == 21) { buf[0] = '\0'; len = cur = view = 0; continue; }
        if (ch == KEY_LEFT && cur > 0) { cur--; continue; }
        if (ch == KEY_RIGHT && cur < len) { cur++; continue; }
        if (ch == KEY_HOME) { cur = 0; continue; }
        if (ch == KEY_END) { cur = len; continue; }

        if ((ch == KEY_BACKSPACE || ch == 127 || ch == 8) && cur > 0) {
            memmove(&buf[cur - 1], &buf[cur], (size_t)(len - cur + 1));
            cur--; len--;
            continue;
        }
        if (ch == KEY_DC && cur < len) {
            memmove(&buf[cur], &buf[cur + 1], (size_t)(len - cur));
            len--;
            continue;
        }
        if (isprint(ch) && len < max_len - 1) {
            memmove(&buf[cur + 1], &buf[cur], (size_t)(len - cur + 1));
            buf[cur++] = (char)ch;
            len++;
            continue;
        }
    }
}

static int menu_dialog(const char *title, const char **options, int count) {
    int h = count + 4, w = 52;
    int y = (LINES - h) / 2, x = (COLS - w) / 2;
    if (w < 30) w = 30;
    if (h < 6) h = 6;

    WINDOW *win = newwin(h, w, y < 0 ? 0 : y, x < 0 ? 0 : x);
    box(win, 0, 0);
    keypad(win, TRUE);

    if (has_colors()) wattron(win, COLOR_PAIR(CP_HEADER) | A_BOLD);
    mvwprintw(win, 0, 2, " %s ", title);
    if (has_colors()) wattroff(win, COLOR_PAIR(CP_HEADER) | A_BOLD);

    int selected = 0;
    int ch;

    while (1) {
        for (int i = 0; i < count; i++) {
            if (i == selected) wattron(win, A_REVERSE);
            mvwprintw(win, i + 2, 2, "%s", options[i]);
            if (i == selected) wattroff(win, A_REVERSE);
        }
        wrefresh(win);

        ch = wgetch(win);

        if (ch == 27) { delwin(win); return -1; }
        if (ch == '\n') { delwin(win); return selected; }
        if (ch == KEY_UP && selected > 0) selected--;
        if (ch == KEY_DOWN && selected < count - 1) selected++;
    }
}

static int confirm_dialog(const char *msg) {
    int h = 5, w = 64;
    int y = (LINES - h) / 2, x = (COLS - w) / 2;
    if (w < 30) w = 30;

    WINDOW *win = newwin(h, w, y < 0 ? 0 : y, x < 0 ? 0 : x);
    box(win, 0, 0);

    mvwprintw(win, 1, 2, "%s", msg);
    mvwprintw(win, 3, 2, "Y:Yes  N:No");
    wrefresh(win);

    int ch = getch();
    delwin(win);

    return (ch == 'y' || ch == 'Y');
}

/* ---------------- Visible lists (respect collapse + order) ---------------- */

static int build_visible_sections(HackPad *nb, int *out_idx, int max_out) {
    int count = 0;
    int collapse_depth = -1;

    for (int i = 0; i < nb->section_count; i++) {
        Section *s = &nb->sections[i];

        if (collapse_depth >= 0) {
            if (s->depth > collapse_depth) continue;
            collapse_depth = -1;
        }

        if (count < max_out) out_idx[count++] = i;

        if (s->collapsed) collapse_depth = s->depth;
    }
    return count;
}

static int build_visible_entries(HackPad *nb, int section_id, int *out_idx, int max_out) {
    int count = 0;
    int collapse_depth = -1;

    for (int i = 0; i < nb->entry_count; i++) {
        Entry *e = &nb->entries[i];
        if (e->section_id != section_id) continue;
        if (!entry_matches_filter(nb, e)) continue;

        if (collapse_depth >= 0) {
            if (e->depth > collapse_depth) continue;
            collapse_depth = -1;
        }

        if (count < max_out) out_idx[count++] = i;

        if (e->collapsed) collapse_depth = e->depth;
    }
    return count;
}

/* ---------------- Subtree end (for correct insertion) ---------------- */

static int section_subtree_end_index(HackPad *nb, int sec_index) {
    if (sec_index < 0 || sec_index >= nb->section_count) return sec_index;
    int d = nb->sections[sec_index].depth;
    int i = sec_index + 1;
    while (i < nb->section_count && nb->sections[i].depth > d) i++;
    return i - 1;
}

static int entry_subtree_end_index_in_section(HackPad *nb, int entry_index) {
    if (entry_index < 0 || entry_index >= nb->entry_count) return entry_index;
    int d = nb->entries[entry_index].depth;
    int sid = nb->entries[entry_index].section_id;
    int i = entry_index + 1;
    while (i < nb->entry_count) {
        if (nb->entries[i].section_id != sid) { i++; continue; }
        if (nb->entries[i].depth <= d) break;
        i++;
    }
    return i - 1;
}

/* ---------------- Draw ---------------- */

static void draw_topbar(HackPad *nb) {
    char secname[MAX_NAME] = "No Section";
    int si = find_section_index_by_id(nb, nb->current_section_id);
    if (si >= 0) strncpy(secname, nb->sections[si].name, sizeof(secname)-1);

    if (has_colors()) attron(COLOR_PAIR(CP_HEADER) | A_BOLD);
    mvprintw(0, 0, " HackPad ");
    if (has_colors()) attroff(COLOR_PAIR(CP_HEADER) | A_BOLD);

    mvprintw(0, 9, "| %s | %s", nb->filename[0] ? nb->filename : "Untitled", secname);

    char flags[128] = {0};
    if (nb->filter != VIEW_ALL) strcat(flags, " FILTER");
    if (nb->show_timestamps) strcat(flags, " TS");

    int fl = (int)strlen(flags);
    if (fl > 0 && COLS > fl + 2) mvprintw(0, COLS - fl - 1, "%s", flags);

    clrtoeol();
}

static void draw_help(WINDOW *w) {
    werase(w);
    box(w, 0, 0);

    if (has_colors()) wattron(w, COLOR_PAIR(CP_HEADER) | A_BOLD);
    mvwprintw(w, 0, 2, " HELP ");
    if (has_colors()) wattroff(w, COLOR_PAIR(CP_HEADER) | A_BOLD);

    int y = 1;
    mvwprintw(w, y++, 2, "Navigation:");
    mvwprintw(w, y++, 4, "h/<- : Focus sections     l/-> : Focus entries");
    mvwprintw(w, y++, 4, "k/^  : Move up            j/v  : Move down");
    mvwprintw(w, y++, 4, "PgUp : Page up            PgDn : Page down");
    y++;
    mvwprintw(w, y++, 2, "Sections:");
    mvwprintw(w, y++, 4, "N : New section (same level, after selected subtree)");
    mvwprintw(w, y++, 4, "B : New sub-section (child, after selected subtree)");
    mvwprintw(w, y++, 4, "O : Collapse/expand section");
    mvwprintw(w, y++, 4, "D : Delete section");
    mvwprintw(w, y++, 4, "C : Set section color");
    y++;
    mvwprintw(w, y++, 2, "Entries:");
    mvwprintw(w, y++, 4, "A : Add entry (after selected entry subtree)");
    mvwprintw(w, y++, 4, "b : Add sub-entry (child of selected entry, after subtree)");
    mvwprintw(w, y++, 4, "E : Edit entry   T : Tags   P : Priority   C : Color");
    mvwprintw(w, y++, 4, "X : Done toggle  * : Pin    O : Collapse/expand entry");
    y++;
    mvwprintw(w, y++, 2, "View / Filter:");
    mvwprintw(w, y++, 4, "F : Filter by tag   V : View mode   R : Reset filters");
    mvwprintw(w, y++, 4, "M : Toggle timestamps");
    y++;
    mvwprintw(w, y++, 2, "File:");
    mvwprintw(w, y++, 4, "S : Save   W : Save as   Y : Export section   Q : Quit");
    y++;
    if (has_colors()) wattron(w, COLOR_PAIR(CP_STATUS));
    mvwprintw(w, y++, 2, "Close help: press ? or ESC");
    if (has_colors()) wattroff(w, COLOR_PAIR(CP_STATUS));

    wrefresh(w);
}

static void apply_color_attr(WINDOW *w, UiColor c, int selected) {
    if (!has_colors() || selected || c == HP_COLOR_NONE) return;
    int cp = color_pair(c);
    if (cp) wattron(w, COLOR_PAIR(cp));
    if (color_is_orange(c)) wattron(w, A_BOLD);
}

static void remove_color_attr(WINDOW *w, UiColor c, int selected) {
    if (!has_colors() || selected || c == HP_COLOR_NONE) return;
    int cp = color_pair(c);
    if (cp) wattroff(w, COLOR_PAIR(cp));
    if (color_is_orange(c)) wattroff(w, A_BOLD);
}

static void draw_sections(WINDOW *w, HackPad *nb) {
    werase(w);
    box(w, 0, 0);

    if (has_colors()) wattron(w, COLOR_PAIR(CP_HEADER) | A_BOLD);
    mvwprintw(w, 0, 2, " SECTIONS ");
    if (has_colors()) wattroff(w, COLOR_PAIR(CP_HEADER) | A_BOLD);

    /* heap visible list to avoid stack/ulimit issues */
    int *vis = (int*)calloc((size_t)nb->section_count + 1, sizeof(int));
    if (!vis) { mvwprintw(w, 1, 2, "OOM"); wrefresh(w); return; }

    int vis_count = build_visible_sections(nb, vis, nb->section_count);

    if (find_section_index_by_id(nb, nb->current_section_id) < 0 && nb->section_count > 0)
        nb->current_section_id = nb->sections[0].id;

    int max_y = getmaxy(w) - 2;
    int row = 1;

    for (int i = 0; i < vis_count && row <= max_y; i++, row++) {
        Section *s = &nb->sections[vis[i]];
        int selected = (nb->focus == FOCUS_SECTIONS && s->id == nb->current_section_id);

        if (selected) wattron(w, A_REVERSE);
        apply_color_attr(w, s->color, selected);

        int indent = s->depth * 2;
        if (indent > 18) indent = 18;

        char icon = s->collapsed ? '+' : '-';
        char linebuf[256];
        snprintf(linebuf, sizeof(linebuf), "%c %*s%s", icon, indent, "", s->name);

        mvwprintw(w, row, 2, "%.*s", getmaxx(w) - 4, linebuf);

        remove_color_attr(w, s->color, selected);
        if (selected) wattroff(w, A_REVERSE);
    }

    free(vis);
    wrefresh(w);
}

static void draw_entries(WINDOW *w, HackPad *nb) {
    werase(w);
    box(w, 0, 0);

    int si = find_section_index_by_id(nb, nb->current_section_id);
    if (si < 0) {
        mvwprintw(w, 1, 2, "No section selected");
        wrefresh(w);
        return;
    }

    Section *sec = &nb->sections[si];

    if (has_colors()) wattron(w, COLOR_PAIR(CP_HEADER) | A_BOLD);
    mvwprintw(w, 0, 2, " %s ", sec->name);
    if (has_colors()) wattroff(w, COLOR_PAIR(CP_HEADER) | A_BOLD);

    if (sec->collapsed) {
        mvwprintw(w, 1, 2, "[Section collapsed - press O to expand]");
        wrefresh(w);
        return;
    }

    /* heap visible list to avoid stack/ulimit issues */
    int *vis = (int*)calloc((size_t)nb->entry_count + 1, sizeof(int));
    if (!vis) { mvwprintw(w, 1, 2, "OOM"); wrefresh(w); return; }
    int vis_count = build_visible_entries(nb, sec->id, vis, nb->entry_count);

    if (vis_count == 0) nb->selected_entry_id = -1;
    if (nb->selected_entry_id != -1) {
        int idx = find_entry_index_by_id(nb, nb->selected_entry_id);
        if (idx < 0 || nb->entries[idx].section_id != sec->id) nb->selected_entry_id = -1;
    }
    if (nb->selected_entry_id == -1 && vis_count > 0) nb->selected_entry_id = nb->entries[vis[0]].id;

    int max_y = getmaxy(w) - 2;
    int row = 1;

    for (int i = 0; i < vis_count && row <= max_y; i++, row++) {
        Entry *e = &nb->entries[vis[i]];
        int selected = (nb->focus == FOCUS_ENTRIES && e->id == nb->selected_entry_id);

        if (selected) wattron(w, A_REVERSE);

        int x = 2;

        int indent = e->depth * 2;
        if (indent > 18) indent = 18;

        char fold = e->collapsed ? '+' : '-';
        mvwprintw(w, row, x, "%c %*s", fold, indent, "");
        x += 2 + indent;

        if (e->pinned) {
            if (has_colors() && !selected) wattron(w, COLOR_PAIR(CP_PIN) | A_BOLD);
            mvwprintw(w, row, x, "* ");
            if (has_colors() && !selected) wattroff(w, COLOR_PAIR(CP_PIN) | A_BOLD);
        } else {
            mvwprintw(w, row, x, "  ");
        }
        x += 2;

        if (e->priority != PRIORITY_NONE) {
            if (has_colors() && !selected) wattron(w, COLOR_PAIR(priority_color_pair(e->priority)) | A_BOLD);
            mvwprintw(w, row, x, "[%s] ", priority_str(e->priority));
            if (has_colors() && !selected) wattroff(w, COLOR_PAIR(priority_color_pair(e->priority)) | A_BOLD);
            x += 5;
        }

        if (e->completed && has_colors() && !selected) wattron(w, COLOR_PAIR(CP_DIM));
        mvwprintw(w, row, x, "%s ", e->completed ? "[x]" : "[ ]");
        x += 4;

        int max_text_len = getmaxx(w) - x - 22;
        if (max_text_len < 10) max_text_len = 10;

        char display_text[MAX_TEXT];
        memset(display_text, 0, sizeof(display_text));
        if ((int)strlen(e->text) > max_text_len) {
            strncpy(display_text, e->text, (size_t)(max_text_len - 3));
            display_text[max_text_len - 3] = '\0';
            strcat(display_text, "...");
        } else {
            strncpy(display_text, e->text, MAX_TEXT - 1);
        }
        apply_color_attr(w, e->color, selected);
        mvwprintw(w, row, x, "%s", display_text);

        if (e->completed && has_colors() && !selected) wattroff(w, COLOR_PAIR(CP_DIM));

        if (e->tag_count > 0 && getmaxx(w) > 40) {
            int tag_x = getmaxx(w) - 20;
            if (tag_x > x + (int)strlen(display_text) + 2) {
                if (has_colors() && !selected) wattron(w, COLOR_PAIR(CP_TAG));
                int shown = 0;
                for (int t = 0; t < e->tag_count && shown < 2; t++, shown++) {
                    mvwprintw(w, row, tag_x, "#%s", e->tags[t]);
                    tag_x += (int)strlen(e->tags[t]) + 2;
                }
                if (e->tag_count > 2) mvwprintw(w, row, tag_x, "+%d", e->tag_count - 2);
                if (has_colors() && !selected) wattroff(w, COLOR_PAIR(CP_TAG));
            }
        }

        if (nb->show_timestamps && getmaxx(w) > 25) {
            char timestr[32] = {0};
            struct tm *tm = localtime(&e->modified);
            if (tm) {
                strftime(timestr, sizeof(timestr), "%m/%d %H:%M", tm);
                mvwprintw(w, row, getmaxx(w) - 13, "%s", timestr);
            }
        }

        remove_color_attr(w, e->color, selected);
        if (selected) wattroff(w, A_REVERSE);
    }

    free(vis);
    wrefresh(w);
}

static void draw_sections_footer(WINDOW *w, HackPad *nb) {
    werase(w);
    if (has_colors()) wattron(w, COLOR_PAIR(CP_STATUS));
    if (nb->focus == FOCUS_SECTIONS) wattron(w, A_BOLD);
    mvwprintw(w, 0, 1, "N new  B sub  O fold  D del  C color");
    if (nb->focus == FOCUS_SECTIONS) wattroff(w, A_BOLD);
    if (has_colors()) wattroff(w, COLOR_PAIR(CP_STATUS));
    wrefresh(w);
}

static void draw_entries_footer(WINDOW *w, HackPad *nb) {
    werase(w);
    if (has_colors()) wattron(w, COLOR_PAIR(CP_STATUS));
    if (nb->focus == FOCUS_ENTRIES) wattron(w, A_BOLD);
    mvwprintw(w, 0, 1, "A add  b sub  E edit  T tag  P pri  C color  X done  * pin");
    if (nb->focus == FOCUS_ENTRIES) wattroff(w, A_BOLD);
    if (has_colors()) wattroff(w, COLOR_PAIR(CP_STATUS));
    wrefresh(w);
}

/* ---------------- Save / Load ---------------- */

static UiColor parse_color_badge(const char *txt) {
    if (!txt) return HP_COLOR_NONE;
    if (strstr(txt, "[RED]"))     return HP_COLOR_RED;
    if (strstr(txt, "[GREEN]"))   return HP_COLOR_GREEN;
    if (strstr(txt, "[YELLOW]"))  return HP_COLOR_YELLOW;
    if (strstr(txt, "[ORANGE]"))  return HP_COLOR_ORANGE;
    if (strstr(txt, "[MAGENTA]")) return HP_COLOR_MAGENTA;
    if (strstr(txt, "[CYAN]"))    return HP_COLOR_CYAN;
    if (strstr(txt, "[WHITE]"))   return HP_COLOR_WHITE;
    return HP_COLOR_NONE;
}

static void save_hackpad(HackPad *nb, const char *file) {
    FILE *f = fopen(file, "w");
    if (!f) { status_msg("ERROR: Could not save file!"); return; }

    time_t now = time(NULL);

    fprintf(f, "# HackPad Modern\n");
    fprintf(f, "Created: %s", ctime(&nb->created_time));
    fprintf(f, "Modified: %s\n", ctime(&now));

    for (int i = 0; i < nb->section_count; i++) {
        Section *s = &nb->sections[i];

        int level = 2 + s->depth;
        for (int k = 0; k < level; k++) fputc('#', f);
        fprintf(f, " %s%s", s->name, s->collapsed ? " [COLLAPSED]" : "");
        if (s->color != HP_COLOR_NONE) fprintf(f, " [%s]", color_str(s->color));
        fprintf(f, "\n\n");

        for (int j = 0; j < nb->entry_count; j++) {
            Entry *e = &nb->entries[j];
            if (e->section_id != s->id) continue;

            int indent = e->depth * 2;
            for (int sp = 0; sp < indent; sp++) fputc(' ', f);

            fprintf(f, "- %s %s", e->completed ? "[x]" : "[ ]", e->text);

            if (e->tag_count > 0) {
                fprintf(f, " #");
                for (int t = 0; t < e->tag_count; t++) {
                    fprintf(f, "%s", e->tags[t]);
                    if (t < e->tag_count - 1) fprintf(f, " #");
                }
            }

            fprintf(f, " {created:%ld,modified:%ld}", (long)e->created, (long)e->modified);

            if (e->priority != PRIORITY_NONE) fprintf(f, " [%s]", priority_str(e->priority));
            if (e->color != HP_COLOR_NONE) fprintf(f, " [%s]", color_str(e->color));
            if (e->pinned) fprintf(f, " [PIN]");
            if (e->collapsed) fprintf(f, " [COLLAPSED]");

            fprintf(f, "\n");
        }
        fprintf(f, "\n");
    }

    fclose(f);
    status_msg("Saved.");
}

static void load_hackpad(HackPad *nb, const char *file) {
    FILE *f = fopen(file, "r");
    if (!f) return;

    char line[MAX_TEXT * 2];
    int section_stack[32];
    int stack_depth = 0;

    int current_section_id = -1;

    int entry_parent_at_depth[256];
    for (int i = 0; i < 256; i++) entry_parent_at_depth[i] = -1;

    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\n")] = 0;

        if (strncmp(line, "Created: ", 9) == 0) {
            struct tm tm = {0};
            char wk[4] = {0}, mon[4] = {0};
            int mday=0, hh=0, mm=0, ss=0, year=0;
            char *t = line + 9;
            if (sscanf(t, "%3s %3s %d %d:%d:%d %d", wk, mon, &mday, &hh, &mm, &ss, &year) == 7) {
                const char *months[] = {"Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"};
                int mon_idx = 0;
                for (int i = 0; i < 12; i++) if (strcmp(mon, months[i]) == 0) { mon_idx = i; break; }
                tm.tm_mday = mday; tm.tm_hour = hh; tm.tm_min = mm; tm.tm_sec = ss;
                tm.tm_year = year - 1900; tm.tm_mon = mon_idx;
                nb->created_time = mktime(&tm);
            }
            continue;
        }

        if (line[0] == '#' && line[1] == '#') {
            int level = count_heading_level(line);
            int depth = level - 2;
            if (depth < 0) depth = 0;
            if (depth > 30) depth = 30;

            char *name = line + level;
            while (*name && isspace((unsigned char)*name)) name++;

            int collapsed = 0;
            char *cpos = strstr(name, " [COLLAPSED]");
            if (cpos) { *cpos = '\0'; collapsed = 1; }
            trim_trailing_spaces(name);

            if (nb->section_count >= MAX_SECTIONS) continue;

            /* parse section color badge from the original line */
            UiColor sc = parse_color_badge(line);

            Section *s = &nb->sections[nb->section_count++];
            memset(s, 0, sizeof(*s));
            s->id = nb->next_section_id++;
            s->depth = depth;
            s->collapsed = collapsed;
            s->color = sc;
            strncpy(s->name, name, MAX_NAME - 1);

            while (stack_depth > depth) stack_depth--;
            if (depth == 0) s->parent_id = -1;
            else s->parent_id = section_stack[depth - 1];

            section_stack[depth] = s->id;
            if (stack_depth <= depth) stack_depth = depth + 1;

            current_section_id = s->id;
            for (int i = 0; i < 256; i++) entry_parent_at_depth[i] = -1;
            continue;
        }

        int lead = count_leading_spaces(line);
        char *p = line + lead;

        if (strncmp(p, "- ", 2) == 0 && current_section_id != -1) {
            if (nb->entry_count >= MAX_ENTRIES) continue;

            int depth = lead / 2;
            if (depth < 0) depth = 0;
            if (depth > 200) depth = 200;

            Entry *e = &nb->entries[nb->entry_count++];
            memset(e, 0, sizeof(*e));
            e->id = nb->next_entry_id++;
            e->section_id = current_section_id;
            e->depth = depth;
            e->parent_id = (depth == 0) ? -1 : entry_parent_at_depth[depth - 1];
            e->color = HP_COLOR_NONE;

            char *txt = p + 2;
            if (strncmp(txt, "[x] ", 4) == 0) { e->completed = 1; txt += 4; }
            else if (strncmp(txt, "[ ] ", 4) == 0) { e->completed = 0; txt += 4; }

            char temp[MAX_TEXT * 2];
            memset(temp, 0, sizeof(temp));
            strncpy(temp, txt, sizeof(temp) - 1);

            char *ts = strstr(temp, "{created:");
            if (ts) {
                long c = 0, m = 0;
                if (sscanf(ts, "{created:%ld,modified:%ld}", &c, &m) == 2) {
                    e->created = (time_t)c;
                    e->modified = (time_t)m;
                } else {
                    e->created = e->modified = time(NULL);
                }
                *ts = '\0';
                trim_trailing_spaces(temp);
            } else {
                e->created = e->modified = time(NULL);
            }

            if (strstr(txt, "[PIN]")) e->pinned = 1;
            if (strstr(txt, "[COLLAPSED]")) e->collapsed = 1;

            if (strstr(txt, "[P0]")) e->priority = PRIORITY_CRITICAL;
            else if (strstr(txt, "[P1]")) e->priority = PRIORITY_HIGH;
            else if (strstr(txt, "[P2]")) e->priority = PRIORITY_MEDIUM;
            else if (strstr(txt, "[P3]")) e->priority = PRIORITY_LOW;
            else e->priority = PRIORITY_NONE;

            e->color = parse_color_badge(txt);

            char *badge = strstr(temp, " [");
            if (badge) { *badge = '\0'; trim_trailing_spaces(temp); }

            e->tag_count = 0;
            char *hash = strchr(temp, '#');
            if (hash && hash > temp) {
                if (hash > temp && *(hash - 1) == ' ') *(hash - 1) = '\0';
                char *tag = strtok(hash + 1, " #");
                while (tag && e->tag_count < MAX_TAGS) {
                    strncpy(e->tags[e->tag_count], tag, MAX_TAG_LEN - 1);
                    e->tags[e->tag_count][MAX_TAG_LEN - 1] = '\0';
                    e->tag_count++;
                    tag = strtok(NULL, " #");
                }
                *hash = '\0';
                trim_trailing_spaces(temp);
            }

            strncpy(e->text, temp, MAX_TEXT - 1);
            e->text[MAX_TEXT - 1] = '\0';

            entry_parent_at_depth[depth] = e->id;
            continue;
        }
    }

    fclose(f);
}

/* ---------------- Actions: insertion helpers ---------------- */

static void insert_section_at(HackPad *nb, int insert_pos, Section *s) {
    if (nb->section_count >= MAX_SECTIONS) return;
    if (insert_pos < 0) insert_pos = 0;
    if (insert_pos > nb->section_count) insert_pos = nb->section_count;

    for (int i = nb->section_count; i > insert_pos; i--) nb->sections[i] = nb->sections[i - 1];
    nb->sections[insert_pos] = *s;
    nb->section_count++;
}

static void insert_entry_at(HackPad *nb, int insert_pos, Entry *e) {
    if (nb->entry_count >= MAX_ENTRIES) return;
    if (insert_pos < 0) insert_pos = 0;
    if (insert_pos > nb->entry_count) insert_pos = nb->entry_count;

    for (int i = nb->entry_count; i > insert_pos; i--) nb->entries[i] = nb->entries[i - 1];
    nb->entries[insert_pos] = *e;
    nb->entry_count++;
}

/* ---------------- Actions ---------------- */

static void add_section_same_level(HackPad *nb) {
    if (nb->section_count >= MAX_SECTIONS) { status_msg("ERROR: Max sections reached"); return; }

    int cur_idx = find_section_index_by_id(nb, nb->current_section_id);
    int parent_id = -1;
    int depth = 0;
    int insert_after = nb->section_count - 1;

    if (cur_idx >= 0) {
        parent_id = nb->sections[cur_idx].parent_id;
        depth = nb->sections[cur_idx].depth;
        insert_after = section_subtree_end_index(nb, cur_idx);
    } else if (nb->section_count > 0) {
        insert_after = section_subtree_end_index(nb, 0);
    }

    char buf[MAX_NAME] = {0};
    if (!line_editor("New Section", buf, MAX_NAME)) return;

    Section s;
    memset(&s, 0, sizeof(s));
    s.id = nb->next_section_id++;
    s.parent_id = parent_id;
    s.depth = depth;
    s.collapsed = 0;
    s.color = HP_COLOR_NONE;
    strncpy(s.name, buf, MAX_NAME - 1);

    insert_section_at(nb, insert_after + 1, &s);

    nb->current_section_id = s.id;
    nb->focus = FOCUS_SECTIONS;
    status_msg("Section created");
}

static void add_sub_section(HackPad *nb) {
    if (nb->section_count >= MAX_SECTIONS) { status_msg("ERROR: Max sections reached"); return; }
    int cur_idx = find_section_index_by_id(nb, nb->current_section_id);
    if (cur_idx < 0) { status_msg("Select a section"); return; }

    char buf[MAX_NAME] = {0};
    if (!line_editor("New Sub-Section", buf, MAX_NAME)) return;

    int insert_after = section_subtree_end_index(nb, cur_idx);

    Section s;
    memset(&s, 0, sizeof(s));
    s.id = nb->next_section_id++;
    s.parent_id = nb->current_section_id;
    s.depth = nb->sections[cur_idx].depth + 1;
    s.collapsed = 0;
    s.color = HP_COLOR_NONE;
    strncpy(s.name, buf, MAX_NAME - 1);

    insert_section_at(nb, insert_after + 1, &s);

    nb->current_section_id = s.id;
    nb->focus = FOCUS_SECTIONS;
    status_msg("Sub-section created");
}

static void add_entry(HackPad *nb, const char *preset) {
    if (nb->entry_count >= MAX_ENTRIES) { status_msg("ERROR: Max entries reached"); return; }
    int si = find_section_index_by_id(nb, nb->current_section_id);
    if (si < 0) { status_msg("Select a section first"); return; }
    if (nb->sections[si].collapsed) { status_msg("Section is collapsed"); return; }

    char buf[MAX_TEXT] = {0};
    if (preset) strncpy(buf, preset, MAX_TEXT - 1);
    if (!line_editor("New Entry", buf, MAX_TEXT)) return;

    /* Insert after selected entry subtree if there's a selected entry in this section; else append at end of section's entries */
    int insert_pos = nb->entry_count;
    int sel_idx = find_entry_index_by_id(nb, nb->selected_entry_id);
    if (sel_idx >= 0 && nb->entries[sel_idx].section_id == nb->current_section_id) {
        insert_pos = entry_subtree_end_index_in_section(nb, sel_idx) + 1;
    } else {
        /* place after last entry belonging to this section */
        for (int i = nb->entry_count - 1; i >= 0; i--) {
            if (nb->entries[i].section_id == nb->current_section_id) { insert_pos = i + 1; break; }
        }
    }

    Entry e;
    memset(&e, 0, sizeof(e));
    e.id = nb->next_entry_id++;
    e.section_id = nb->current_section_id;
    e.parent_id = -1;
    e.depth = 0;
    e.collapsed = 0;
    e.color = HP_COLOR_NONE;
    strncpy(e.text, buf, MAX_TEXT - 1);
    e.created = e.modified = time(NULL);

    insert_entry_at(nb, insert_pos, &e);

    nb->selected_entry_id = e.id;
    nb->focus = FOCUS_ENTRIES;
    status_msg("Entry added");
}

static void add_sub_entry(HackPad *nb) {
    if (nb->entry_count >= MAX_ENTRIES) { status_msg("ERROR: Max entries reached"); return; }
    int ei = find_entry_index_by_id(nb, nb->selected_entry_id);
    if (ei < 0) { status_msg("Select an entry first"); return; }

    Entry *parent = &nb->entries[ei];

    char buf[MAX_TEXT] = {0};
    if (!line_editor("New Sub-Entry", buf, MAX_TEXT)) return;

    /* Insert after parent's subtree */
    int insert_pos = entry_subtree_end_index_in_section(nb, ei) + 1;

    Entry e;
    memset(&e, 0, sizeof(e));
    e.id = nb->next_entry_id++;
    e.section_id = parent->section_id;
    e.parent_id = parent->id;
    e.depth = parent->depth + 1;
    e.collapsed = 0;
    e.color = HP_COLOR_NONE;
    strncpy(e.text, buf, MAX_TEXT - 1);
    e.created = e.modified = time(NULL);

    insert_entry_at(nb, insert_pos, &e);

    nb->selected_entry_id = e.id;
    nb->focus = FOCUS_ENTRIES;
    status_msg("Sub-entry added");
}

static void edit_entry(HackPad *nb) {
    int ei = find_entry_index_by_id(nb, nb->selected_entry_id);
    if (ei < 0) { status_msg("No entry selected"); return; }

    Entry *e = &nb->entries[ei];
    char buf[MAX_TEXT];
    memset(buf, 0, sizeof(buf));
    strncpy(buf, e->text, MAX_TEXT - 1);

    if (line_editor("Edit Entry", buf, MAX_TEXT)) {
        strncpy(e->text, buf, MAX_TEXT - 1);
        e->modified = time(NULL);
        status_msg("Entry updated");
    }
}

static void edit_tags(HackPad *nb) {
    int ei = find_entry_index_by_id(nb, nb->selected_entry_id);
    if (ei < 0) { status_msg("No entry selected"); return; }
    Entry *e = &nb->entries[ei];

    char buf[MAX_TEXT] = {0};
    for (int i = 0; i < e->tag_count; i++) {
        if (i) strncat(buf, " ", sizeof(buf) - strlen(buf) - 1);
        strncat(buf, e->tags[i], sizeof(buf) - strlen(buf) - 1);
    }

    if (line_editor("Tags (space/comma-separated)", buf, MAX_TEXT)) {
        e->tag_count = 0;
        char *tag = strtok(buf, " ,");
        while (tag && e->tag_count < MAX_TAGS) {
            strncpy(e->tags[e->tag_count], tag, MAX_TAG_LEN - 1);
            e->tags[e->tag_count][MAX_TAG_LEN - 1] = '\0';
            e->tag_count++;
            tag = strtok(NULL, " ,");
        }
        e->modified = time(NULL);
        status_msg("Tags updated");
    }
}

static void set_priority(HackPad *nb) {
    int ei = find_entry_index_by_id(nb, nb->selected_entry_id);
    if (ei < 0) { status_msg("No entry selected"); return; }

    const char *opts[] = {"None","Low","Medium","High","Critical"};
    int choice = menu_dialog("Set Priority", opts, 5);
    if (choice >= 0) {
        nb->entries[ei].priority = (Priority)choice;
        nb->entries[ei].modified = time(NULL);
        status_msg("Priority updated");
    }
}

static void set_entry_color(HackPad *nb) {
    int ei = find_entry_index_by_id(nb, nb->selected_entry_id);
    if (ei < 0) { status_msg("No entry selected"); return; }

    const char *opts[] = {"None","Red","Green","Yellow","Orange","Magenta","Cyan","White"};
    int choice = menu_dialog("Set Entry Color", opts, 8);
    if (choice >= 0) {
        nb->entries[ei].color = (UiColor)choice;
        nb->entries[ei].modified = time(NULL);
        status_msg("Entry color updated");
    }
}

static void set_section_color(HackPad *nb) {
    int si = find_section_index_by_id(nb, nb->current_section_id);
    if (si < 0) { status_msg("No section selected"); return; }

    const char *opts[] = {"None","Red","Green","Yellow","Orange","Magenta","Cyan","White"};
    int choice = menu_dialog("Set Section Color", opts, 8);
    if (choice >= 0) {
        nb->sections[si].color = (UiColor)choice;
        status_msg("Section color updated");
    }
}

static void toggle_complete(HackPad *nb) {
    int ei = find_entry_index_by_id(nb, nb->selected_entry_id);
    if (ei < 0) { status_msg("No entry selected"); return; }
    nb->entries[ei].completed = !nb->entries[ei].completed;
    nb->entries[ei].modified = time(NULL);
    status_msg(nb->entries[ei].completed ? "Marked complete" : "Marked incomplete");
}

static void toggle_pin(HackPad *nb) {
    int ei = find_entry_index_by_id(nb, nb->selected_entry_id);
    if (ei < 0) { status_msg("No entry selected"); return; }
    nb->entries[ei].pinned = !nb->entries[ei].pinned;
    nb->entries[ei].modified = time(NULL);
    status_msg(nb->entries[ei].pinned ? "Pinned" : "Unpinned");
}

static void toggle_fold(HackPad *nb) {
    if (nb->focus == FOCUS_SECTIONS) {
        int si = find_section_index_by_id(nb, nb->current_section_id);
        if (si >= 0) nb->sections[si].collapsed = !nb->sections[si].collapsed;
    } else {
        int ei = find_entry_index_by_id(nb, nb->selected_entry_id);
        if (ei >= 0) nb->entries[ei].collapsed = !nb->entries[ei].collapsed;
    }
}

static void delete_section(HackPad *nb) {
    int si = find_section_index_by_id(nb, nb->current_section_id);
    if (si < 0) { status_msg("No section selected"); return; }

    char msg[256];
    snprintf(msg, sizeof(msg), "Delete section '%s' (entries inside will be deleted)?", nb->sections[si].name);
    if (!confirm_dialog(msg)) { status_msg("Cancelled"); return; }

    int del_id = nb->sections[si].id;
    int del_depth = nb->sections[si].depth;

    /* delete section subtree in one shot (since order is depth-first) */
    int end = section_subtree_end_index(nb, si);

    /* delete entries belonging to any section in this subtree */
    for (int i = 0; i < nb->entry_count; ) {
        int secid = nb->entries[i].section_id;
        int in_subtree = 0;
        for (int sidx = si; sidx <= end; sidx++) {
            if (nb->sections[sidx].id == secid) { in_subtree = 1; break; }
        }
        if (in_subtree) {
            for (int k = i; k < nb->entry_count - 1; k++) nb->entries[k] = nb->entries[k + 1];
            nb->entry_count--;
            continue;
        }
        i++;
    }

    /* remove the section subtree */
    int remove_count = end - si + 1;
    for (int i = si; i + remove_count < nb->section_count; i++) {
        nb->sections[i] = nb->sections[i + remove_count];
    }
    nb->section_count -= remove_count;

    /* pick a sane next selection */
    if (nb->section_count > 0) {
        int pick = si;
        if (pick >= nb->section_count) pick = nb->section_count - 1;
        nb->current_section_id = nb->sections[pick].id;
    } else {
        nb->current_section_id = -1;
    }

    nb->selected_entry_id = -1;
    (void)del_id; (void)del_depth;
    status_msg("Section deleted");
}

static void delete_entry(HackPad *nb) {
    int ei = find_entry_index_by_id(nb, nb->selected_entry_id);
    if (ei < 0) { status_msg("No entry selected"); return; }

    if (!confirm_dialog("Delete this entry (and its sub-entries)?")) { status_msg("Cancelled"); return; }

    int start = ei;
    int end = entry_subtree_end_index_in_section(nb, ei);
    int remove_count = end - start + 1;
    int sid = nb->entries[start].section_id;

    /* remove contiguous subtree entries (depth-first in this section) */
    for (int i = start; i + remove_count < nb->entry_count; i++) {
        nb->entries[i] = nb->entries[i + remove_count];
    }
    nb->entry_count -= remove_count;

    /* clear selection */
    nb->selected_entry_id = -1;

    /* try to select next visible entry in same section */
    for (int i = start; i < nb->entry_count; i++) {
        if (nb->entries[i].section_id == sid) { nb->selected_entry_id = nb->entries[i].id; break; }
    }
    status_msg("Entry deleted");
}

/* ---------------- Filter / Export ---------------- */

static void filter_by_tag(HackPad *nb) {
    if (line_editor("Filter by tag", nb->filter_tag, MAX_TAG_LEN)) {
        nb->filter = VIEW_TAGGED;
        status_msg("Filtering by tag (R to reset)");
    }
}

static void change_view_mode(HackPad *nb) {
    const char *options[] = {"All entries","By tag","By priority","Completed only","Incomplete only"};
    int choice = menu_dialog("View Mode", options, 5);
    if (choice >= 0) {
        nb->filter = (ViewFilter)choice;
        if (choice == VIEW_PRIORITY) {
            const char *pri_opts[] = {"Low (P3)","Medium (P2)","High (P1)","Critical (P0)"};
            int pri = menu_dialog("Select Priority", pri_opts, 4);
            if (pri >= 0) {
                nb->filter_priority = (Priority)(pri + 1);
                status_msg("View mode changed");
            } else {
                nb->filter = VIEW_ALL;
            }
        } else {
            status_msg("View mode changed");
        }
    }
}

static void reset_filters(HackPad *nb) {
    nb->filter = VIEW_ALL;
    nb->filter_tag[0] = '\0';
    status_msg("Filters reset");
}

static void export_section(HackPad *nb) {
    int si = find_section_index_by_id(nb, nb->current_section_id);
    if (si < 0) { status_msg("No section selected"); return; }

    char filename[256];
    snprintf(filename, sizeof(filename), "%s_export.md", nb->sections[si].name);
    if (!line_editor("Export to", filename, 256)) return;

    FILE *f = fopen(filename, "w");
    if (!f) { status_msg("ERROR: Could not create export file"); return; }

    fprintf(f, "# %s\n\n", nb->sections[si].name);

    int *vis = (int*)calloc((size_t)nb->entry_count + 1, sizeof(int));
    if (!vis) { fclose(f); status_msg("OOM"); return; }
    int vis_count = build_visible_entries(nb, nb->sections[si].id, vis, nb->entry_count);

    for (int i = 0; i < vis_count; i++) {
        Entry *e = &nb->entries[vis[i]];
        int indent = e->depth * 2;
        for (int sp = 0; sp < indent; sp++) fputc(' ', f);
        fprintf(f, "- %s %s", e->completed ? "[x]" : "[ ]", e->text);

        if (e->tag_count > 0) {
            fprintf(f, " (");
            for (int t = 0; t < e->tag_count; t++) {
                fprintf(f, "#%s", e->tags[t]);
                if (t < e->tag_count - 1) fprintf(f, " ");
            }
            fprintf(f, ")");
        }
        if (e->priority != PRIORITY_NONE) fprintf(f, " [%s]", priority_str(e->priority));
        if (e->color != HP_COLOR_NONE) fprintf(f, " [%s]", color_str(e->color));
        if (e->pinned) fprintf(f, " [PIN]");
        fprintf(f, "\n");
    }

    free(vis);
    fclose(f);
    status_msg("Section exported");
}

/* ---------------- Navigation ---------------- */

static void move_section_selection(HackPad *nb, int delta) {
    int *vis = (int*)calloc((size_t)nb->section_count + 1, sizeof(int));
    if (!vis) return;
    int vis_count = build_visible_sections(nb, vis, nb->section_count);
    if (vis_count <= 0) { free(vis); return; }

    int cur_pos = 0;
    for (int i = 0; i < vis_count; i++) {
        if (nb->sections[vis[i]].id == nb->current_section_id) { cur_pos = i; break; }
    }

    int new_pos = cur_pos + delta;
    if (new_pos < 0) new_pos = 0;
    if (new_pos >= vis_count) new_pos = vis_count - 1;

    nb->current_section_id = nb->sections[vis[new_pos]].id;
    nb->selected_entry_id = -1;

    free(vis);
}

static void move_entry_selection(HackPad *nb, int delta) {
    int si = find_section_index_by_id(nb, nb->current_section_id);
    if (si < 0) return;
    int sid = nb->sections[si].id;

    int *vis = (int*)calloc((size_t)nb->entry_count + 1, sizeof(int));
    if (!vis) return;
    int vis_count = build_visible_entries(nb, sid, vis, nb->entry_count);
    if (vis_count <= 0) { nb->selected_entry_id = -1; free(vis); return; }

    int cur_pos = 0;
    for (int i = 0; i < vis_count; i++) {
        if (nb->entries[vis[i]].id == nb->selected_entry_id) { cur_pos = i; break; }
    }

    int new_pos = cur_pos + delta;
    if (new_pos < 0) new_pos = 0;
    if (new_pos >= vis_count) new_pos = vis_count - 1;

    nb->selected_entry_id = nb->entries[vis[new_pos]].id;
    free(vis);
}

/* ---------------- Resize-safe window management ---------------- */

static void destroy_windows(HackPad *nb) {
    if (nb->secw)  { delwin(nb->secw);  nb->secw = NULL; }
    if (nb->entw)  { delwin(nb->entw);  nb->entw = NULL; }
    if (nb->secf)  { delwin(nb->secf);  nb->secf = NULL; }
    if (nb->entf)  { delwin(nb->entf);  nb->entf = NULL; }
    if (nb->helpw) { delwin(nb->helpw); nb->helpw = NULL; }
}

static void create_windows(HackPad *nb) {
    destroy_windows(nb);

    nb->sw = 28;
    if (nb->sw > COLS - 30) nb->sw = (COLS > 60) ? 28 : (COLS / 2);
    if (nb->sw < 20) nb->sw = (COLS > 40) ? 20 : (COLS / 2);
    if (nb->sw < 10) nb->sw = 10;

    int main_h = LINES - 3;
    if (main_h < 5) main_h = 5;

    int ent_w = COLS - nb->sw;
    if (ent_w < 10) ent_w = 10;

    nb->secw  = newwin(main_h, nb->sw, 1, 0);
    nb->entw  = newwin(main_h, ent_w, 1, nb->sw);

    nb->secf  = newwin(1, nb->sw, LINES - 2, 0);
    nb->entf  = newwin(1, ent_w, LINES - 2, nb->sw);

    nb->helpw = newwin(LINES - 2, COLS, 1, 0);

    keypad(nb->secw, TRUE);
    keypad(nb->entw, TRUE);
    keypad(nb->secf, TRUE);
    keypad(nb->entf, TRUE);
    keypad(nb->helpw, TRUE);
}

static void redraw_all(HackPad *nb) {
    erase();
    refresh();
    draw_topbar(nb);

    if (nb->show_help) {
        draw_help(nb->helpw);
    } else {
        draw_sections(nb->secw, nb);
        draw_entries(nb->entw, nb);
        draw_sections_footer(nb->secf, nb);
        draw_entries_footer(nb->entf, nb);
    }
    status_msg("Ready. ? help | Q quit");
}

/* ---------------- MAIN ---------------- */

int main(int argc, char *argv[]) {
    HackPad nb;
    memset(&nb, 0, sizeof(nb));

    nb.focus = FOCUS_SECTIONS;
    nb.created_time = time(NULL);
    nb.filter = VIEW_ALL;

    nb.next_section_id = 1;
    nb.next_entry_id = 1;

    const char *file = (argc > 1) ? argv[1] : "HackPad.md";
    strncpy(nb.filename, file, sizeof(nb.filename) - 1);

    load_hackpad(&nb, file);

    if (nb.section_count == 0) {
        const char *defaults[] = {"Hosts", "IPs", "Credentials", "Exploits", "Vulnerabilities", "Notes"};
        for (int i = 0; i < 5; i++) {
            Section *s = &nb.sections[nb.section_count++];
            memset(s, 0, sizeof(*s));
            s->id = nb.next_section_id++;
            s->parent_id = -1;
            s->depth = 0;
            s->collapsed = 0;
            s->color = HP_COLOR_NONE;
            strncpy(s->name, defaults[i], MAX_NAME - 1);
        }
    }

    nb.current_section_id = nb.sections[0].id;
    nb.selected_entry_id = -1;

    ui_init();
    create_windows(&nb);

    redraw_all(&nb);

    int ch;
    while ((ch = getch()) != 'q' && ch != 'Q') {

        /* Resize: rebuild windows and redraw */
        if (ch == KEY_RESIZE) {
            /* let ncurses update LINES/COLS */
            endwin();
            refresh();
            clear();
            create_windows(&nb);
            redraw_all(&nb);
            continue;
        }

        /* Help overlay: MUST be closable */
        if (nb.show_help) {
            if (ch == '?' || ch == 27) { /* '?' or ESC closes help */
                nb.show_help = 0;
                redraw_all(&nb);
            } else if (ch == 'q' || ch == 'Q') {
                break;
            } else {
                draw_help(nb.helpw);
            }
            continue;
        }

        switch (ch) {
            case '?':
                nb.show_help = 1;
                draw_help(nb.helpw);
                break;

            case KEY_LEFT:
            case 'h':
                nb.focus = FOCUS_SECTIONS;
                break;

            case KEY_RIGHT:
            case 'l':
                nb.focus = FOCUS_ENTRIES;
                break;

            case KEY_UP:
            case 'k':
                if (nb.focus == FOCUS_SECTIONS) move_section_selection(&nb, -1);
                else move_entry_selection(&nb, -1);
                break;

            case KEY_DOWN:
            case 'j':
                if (nb.focus == FOCUS_SECTIONS) move_section_selection(&nb, +1);
                else move_entry_selection(&nb, +1);
                break;

            case KEY_PPAGE:
                if (nb.focus == FOCUS_ENTRIES) move_entry_selection(&nb, -10);
                break;

            case KEY_NPAGE:
                if (nb.focus == FOCUS_ENTRIES) move_entry_selection(&nb, +10);
                break;

            case 'n':
            case 'N':
                add_section_same_level(&nb);
                break;

            case 'B':
                add_sub_section(&nb);
                break;

            case 'a':
            case 'A':
                add_entry(&nb, NULL);
                break;

            case 'b':
                if (nb.focus == FOCUS_ENTRIES) add_sub_entry(&nb);
                break;

            case '1': add_entry(&nb, host_template); break;
            case '2': add_entry(&nb, cred_template); break;
            case '3': add_entry(&nb, exploit_template); break;
            case '4': add_entry(&nb, vuln_template); break;

            case 'e':
            case 'E':
                edit_entry(&nb);
                break;

            case 't':
            case 'T':
                edit_tags(&nb);
                break;

            case 'p':
            case 'P':
                set_priority(&nb);
                break;

            case 'c':
            case 'C':
                if (nb.focus == FOCUS_SECTIONS) set_section_color(&nb);
                else set_entry_color(&nb);
                break;

            case 'x':
            case 'X':
                toggle_complete(&nb);
                break;

            case '*':
                toggle_pin(&nb);
                break;

            case 'o':
            case 'O':
                toggle_fold(&nb);
                break;

            case 'd':
            case 'D':
                if (nb.focus == FOCUS_SECTIONS) delete_section(&nb);
                else delete_entry(&nb);
                break;

            case 'f':
            case 'F':
                filter_by_tag(&nb);
                break;

            case 'v':
            case 'V':
                change_view_mode(&nb);
                break;

            case 'r':
            case 'R':
                reset_filters(&nb);
                break;

            case 'm':
            case 'M':
                nb.show_timestamps = !nb.show_timestamps;
                status_msg(nb.show_timestamps ? "Timestamps ON" : "Timestamps OFF");
                break;

            case 'y':
            case 'Y':
                export_section(&nb);
                break;

            case 's':
            case 'S':
                save_hackpad(&nb, nb.filename);
                break;

            case 'w':
            case 'W': {
                char newfile[256] = {0};
                strncpy(newfile, nb.filename, sizeof(newfile) - 1);
                if (line_editor("Save As", newfile, (int)sizeof(newfile))) {
                    strncpy(nb.filename, newfile, sizeof(nb.filename) - 1);
                    save_hackpad(&nb, nb.filename);
                }
            } break;
        }

        draw_topbar(&nb);
        draw_sections(nb.secw, &nb);
        draw_entries(nb.entw, &nb);
        draw_sections_footer(nb.secf, &nb);
        draw_entries_footer(nb.entf, &nb);
    }

    if (confirm_dialog("Save before quitting?")) save_hackpad(&nb, nb.filename);

    destroy_windows(&nb);
    ui_shutdown();
    return 0;
}
