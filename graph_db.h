/* darkstat 3
 * copyright (c) 2006-2011 Emil Mikulic.
 *
 * graph_db.h: round robin database for graph data
 */
#ifndef __DARKSTAT_GRAPH_DB_H
#define __DARKSTAT_GRAPH_DB_H

#include <stdint.h> /* for uint64_t on Linux and OS X */

enum graph_dir {
   MIN_GRAPH_DIR = 1,
   GRAPH_IN = 1,
   GRAPH_OUT = 2,
   MAX_GRAPH_DIR = 2
};

void graph_init(void);
void graph_reset(void);
void graph_free(void);
void graph_acct(uint64_t amount, enum graph_dir dir);
void graph_rotate(void);
int graph_import(const int fd);
int graph_export(const int fd);

struct str *html_front_page(void);
struct str *xml_graphs(void);

#endif
/* vim:set ts=3 sw=3 tw=78 expandtab: */
