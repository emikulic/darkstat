/* darkstat 3
 * copyright (c) 2006-2008 Emil Mikulic.
 *
 * graph_db.c: round robin database for graph data
 *
 * You may use, modify and redistribute this file under the terms of the
 * GNU General Public License version 2. (see COPYING.GPL)
 */

#include <sys/types.h>
#include <netinet/in.h> /* for in_addr_t (db.h needs it) */

#include "cap.h"
#include "conv.h"
#include "darkstat.h"
#include "db.h"
#include "acct.h"
#include "err.h"
#include "str.h"
#include "html.h" /* FIXME: should be pushed into a .c file? */
#include "graph_db.h"
#include "now.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h> /* for memcpy() */

#define GRAPH_WIDTH "320"
#define GRAPH_HEIGHT "200"

extern const char *interface;

struct graph {
   uint64_t *in, *out;
   unsigned int offset; /* i.e. seconds start at 0, days start at 1 */
   unsigned int pos, num_bars;
   const char *unit;
   unsigned int bar_secs; /* one bar represents <n> seconds */
};

static struct graph
   graph_secs = {NULL, NULL, 0, 0, 60, "seconds", 1},
   graph_mins = {NULL, NULL, 0, 0, 60, "minutes", 60},
   graph_hrs  = {NULL, NULL, 0, 0, 24, "hours",   3600},
   graph_days = {NULL, NULL, 1, 0, 31, "days",    86400};

static struct graph *graph_db[] = {
   &graph_secs, &graph_mins, &graph_hrs, &graph_days
};

static unsigned int graph_db_size = sizeof(graph_db)/sizeof(*graph_db);

static time_t start_time, last_time;

void
graph_init(void)
{
   unsigned int i;
   for (i=0; i<graph_db_size; i++) {
      graph_db[i]->in  = xmalloc(sizeof(uint64_t) * graph_db[i]->num_bars);
      graph_db[i]->out = xmalloc(sizeof(uint64_t) * graph_db[i]->num_bars);
   }
   start_time = time(NULL);
   graph_reset();
}

static void
zero_graph(struct graph *g)
{
   memset(g->in,  0, sizeof(uint64_t) * g->num_bars);
   memset(g->out, 0, sizeof(uint64_t) * g->num_bars);
}

void
graph_reset(void)
{
   unsigned int i;
   for (i=0; i<graph_db_size; i++)
      zero_graph(graph_db[i]);
   last_time = 0;
}

void
graph_free(void)
{
   unsigned int i;
   for (i=0; i<graph_db_size; i++) {
      free(graph_db[i]->in);
      free(graph_db[i]->out);
   }
}

void
graph_acct(uint64_t amount, enum graph_dir dir)
{
   unsigned int i;
   for (i=0; i<graph_db_size; i++)
    switch (dir) {
     case GRAPH_IN:  graph_db[i]->in[  graph_db[i]->pos ] += amount; break;
     case GRAPH_OUT: graph_db[i]->out[ graph_db[i]->pos ] += amount; break;
     default: errx(1, "unknown graph_dir in graph_acct: %d", dir);
    }
}

/* Advance a graph: advance the pos, zeroing out bars as we move. */
static void
advance(struct graph *g, const unsigned int pos)
{
   if (g->pos == pos)
      return; /* didn't need to advance */
   do {
      g->pos = (g->pos + 1) % g->num_bars;
      g->in[g->pos] = g->out[g->pos] = 0;
   } while (g->pos != pos);
}

/* Rotate a graph: rotate all bars so that the bar at the current pos is moved
 * to the newly given pos.  This is non-destructive. */
static void
rotate(struct graph *g, const unsigned int pos)
{
   uint64_t *tmp;
   unsigned int i, ofs;
   size_t size;

   if (pos == g->pos)
      return; /* nothing to rotate */

   size = sizeof(*tmp) * g->num_bars;
   tmp = xmalloc(size);
   ofs = g->num_bars + pos - g->pos;

   for (i=0; i<g->num_bars; i++)
      tmp[ (i+ofs) % g->num_bars ] = g->in[i];
   memcpy(g->in, tmp, size);

   for (i=0; i<g->num_bars; i++)
      tmp[ (i+ofs) % g->num_bars ] = g->out[i];
   memcpy(g->out, tmp, size);

   free(tmp);
   assert(pos == ( (g->pos + ofs) % g->num_bars ));
   g->pos = pos;
}

static void
graph_resync(const time_t new_time)
{
   struct tm *tm;
   /*
    * If time went backwards, we assume that real time is continuous and that
    * the time adjustment should only affect display.  i.e., if we have:
    *
    * second 15: 12  bytes
    * second 16: 345 bytes
    * second 17: <-- current pos
    *
    * and time goes backwards to second 8, we will shift the graph around to
    * get:
    *
    * second 6: 12  bytes
    * second 7: 345 bytes
    * second 8: <-- current pos
    *
    * Note that we don't make any corrections for time being stepped forward.
    * We rely on graph advancement to happen at the correct real time to
    * account for, for example, bandwidth used per day.
    */
   assert(new_time < last_time);

   tm = localtime(&new_time);
   if (tm->tm_sec == 60)
      tm->tm_sec = 59; /* mis-handle leap seconds */

   rotate(&graph_secs, tm->tm_sec);
   rotate(&graph_mins, tm->tm_min);
   rotate(&graph_hrs, tm->tm_hour);
   rotate(&graph_days, tm->tm_mday - 1);

   last_time = new_time;
}

void
graph_rotate(void)
{
   time_t t, td;
   struct tm *tm;
   unsigned int i;

   t = now;

   if (last_time == 0) {
      verbosef("first rotate");
      last_time = t;
      tm = localtime(&t);
      if (tm->tm_sec == 60)
         tm->tm_sec = 59; /* mis-handle leap seconds */

      graph_secs.pos = tm->tm_sec;
      graph_mins.pos = tm->tm_min;
      graph_hrs.pos = tm->tm_hour;
      graph_days.pos = tm->tm_mday - 1;
      return;
   }

   if (t == last_time)
      return; /* superfluous rotate */

   if (t < last_time) {
      verbosef("time went backwards! (from %u to %u, offset is %d)",
         (unsigned int)last_time, (unsigned int)t, (int)(t - last_time));
      graph_resync(t);
      return;
   }

   /* else, normal rotation */
   td = t - last_time;
   last_time = t;
   tm = localtime(&t);
   if (tm->tm_sec == 60)
      tm->tm_sec = 59; /* mis-handle leap seconds */

   /* zero out graphs which have been completely rotated through */
   for (i=0; i<graph_db_size; i++)
      if (td >= (int)(graph_db[i]->num_bars * graph_db[i]->bar_secs))
         zero_graph(graph_db[i]);

   /* advance the current position, zeroing up to it */
   advance(&graph_secs, tm->tm_sec);
   advance(&graph_mins, tm->tm_min);
   advance(&graph_hrs, tm->tm_hour);
   advance(&graph_days, tm->tm_mday - 1);
}

/* ---------------------------------------------------------------------------
 * Database Import: Grab graphs from a file provided by the caller.
 *
 * This function will retrieve the data sans the header.  We expect the caller
 * to have validated the header of the segment, and left the file position at
 * the start of the data.
 */
int
graph_import(const int fd)
{
   uint64_t last;
   unsigned int i, j;

   if (!read64(fd, &last)) return 0;
   last_time = (time_t)last;

   for (i=0; i<graph_db_size; i++) {
      unsigned char num_bars, pos;
      unsigned int filepos = xtell(fd);

      if (!read8(fd, &num_bars)) return 0;
      if (!read8(fd, &pos)) return 0;

      verbosef("at file pos %u, importing graph with %u bars",
         filepos, (unsigned int)num_bars);

      if (pos >= num_bars) {
         warn("pos is %u, should be < num_bars which is %u",
            (unsigned int)pos, (unsigned int)num_bars);
         return 0;
      }

      if (graph_db[i]->num_bars != num_bars) {
         warn("num_bars is %u, expecting %u",
            (unsigned int)num_bars, graph_db[i]->num_bars);
         return 0;
      }

      graph_db[i]->pos = pos;
      for (j=0; j<num_bars; j++) {
         if (!read64(fd, &(graph_db[i]->in[j]))) return 0;
         if (!read64(fd, &(graph_db[i]->out[j]))) return 0;
      }
   }

   return 1;
}

/* ---------------------------------------------------------------------------
 * Database Export: Dump hosts_db into a file provided by the caller.
 * The caller is responsible for writing out the header first.
 */
int
graph_export(const int fd)
{
   unsigned int i, j;

   if (!write64(fd, (uint64_t)last_time)) return 0;
   for (i=0; i<graph_db_size; i++) {
      if (!write8(fd, graph_db[i]->num_bars)) return 0;
      if (!write8(fd, graph_db[i]->pos)) return 0;

      for (j=0; j<graph_db[i]->num_bars; j++) {
         if (!write64(fd, graph_db[i]->in[j])) return 0;
         if (!write64(fd, graph_db[i]->out[j])) return 0;
      }
   }
   return 1;
}

/* ---------------------------------------------------------------------------
 * Web interface: front page!
 */
struct str *
html_front_page(void)
{
   struct str *buf, *rf;
   unsigned int i;
   char start_when[100];

   buf = str_make();
   str_append(buf, html_header_1);
   str_appendf(buf, "<title>" PACKAGE_STRING " : graphs (%s)</title>\n",
               interface);
   str_append(buf, "<script src=\"graph.js\" type=\"text/javascript\">"
                   "</script>\n");
   str_append(buf, html_header_2);
   str_appendf(buf, "<h2 class=\"pageheader\">Graphs (%s)</h2>\n", interface);

   str_append(buf, "<p>\n");

   str_append(buf, "<b>Running for</b> <span id=\"rf\">");
   rf = length_of_time(now - start_time);
   /* FIXME: use a more monotonic clock perhaps? */
   str_appendstr(buf, rf);
   str_free(rf);
   str_append(buf, "</span>");

   if (strftime(start_when, sizeof(start_when),
      "%Y-%m-%d %H:%M:%S %Z%z", localtime(&start_time)) != 0)
      str_appendf(buf, "<b>, since</b> %s", start_when);

   str_appendf(buf,"<b>.</b><br/>\n"
      "<b>Total</b> <span id=\"tb\">%'qu</span> <b>bytes, "
      "in</b> <span id=\"tp\">%'qu</span> <b>packets.</b> "
      "(<span id=\"pc\">%'u</span> <b>captured,</b> "
      "<span id=\"pd\">%'u</span> <b>dropped)</b><br/>\n"
      "</p>\n",
      total_bytes,
      total_packets,
      pkts_recv, pkts_drop);

   str_append(buf,
      "<div id=\"graphs\">\n"
      "Graphs require JavaScript.\n"
      "<script type=\"text/javascript\">\n"
      "//<![CDATA[\n"
      "var graph_width = " GRAPH_WIDTH ";\n"
      "var graph_height = " GRAPH_HEIGHT ";\n"
      "var bar_gap = 1;\n"
      "var graphs_uri = \"/graphs.xml\";\n"
      "var graphs = [\n"
   );

   for (i=0; i<graph_db_size; i++)
      str_appendf(buf,
         " { id:\"g%u\", "
            "name:\"%s\", "
            "title:\"last %u %s\", "
            "bar_secs:%u"
         " }%s\n",
         i, graph_db[i]->unit, graph_db[i]->num_bars, graph_db[i]->unit,
         graph_db[i]->bar_secs, (i < graph_db_size-1) ? "," : "");
      /* trailing comma breaks on IE, makes the array one element longer */

   str_append(buf,
      "];\n"
      "window.onload = graphs_init;\n"
      "//]]>\n"
      "</script>\n"
      "</div>\n"
   );

   str_append(buf, html_footer);
   return (buf);
}

/* ---------------------------------------------------------------------------
 * Web interface: graphs.xml
 */
struct str *
xml_graphs(void)
{
   unsigned int i, j;
   struct str *buf = str_make(), *rf;

   str_appendf(buf, "<graphs tp=\"%qu\" tb=\"%qu\" pc=\"%u\" pd=\"%u\" rf=\"",
      total_packets, total_bytes, pkts_recv, pkts_drop);
   rf = length_of_time(now - start_time);
   str_appendstr(buf, rf);
   str_free(rf);
   str_append(buf, "\">\n");

   for (i=0; i<graph_db_size; i++) {
      const struct graph *g = graph_db[i];

      str_appendf(buf, "<%s>\n", g->unit);
      j = g->pos;
      do {
         j = (j + 1) % g->num_bars;
         /* <element pos="" in="" out=""/> */
         str_appendf(buf, "<e p=\"%u\" i=\"%qu\" o=\"%qu\"/>\n",
            g->offset + j, g->in[j], g->out[j]);
      } while (j != g->pos);
      str_appendf(buf, "</%s>\n", g->unit);
   }
   str_append(buf, "</graphs>\n");
   return (buf);
}

/* vim:set ts=3 sw=3 tw=78 expandtab: */
