/* darkstat 3
 *
 * html.h: HTML header/footer templating for web interface.
 * copyright (c) 2006 Ben Stewart.
 * copyright (c) 2010 Malte S. Stretz.
 */
#ifndef __DARKSTAT_HTML_H
#define __DARKSTAT_HTML_H

void html_open(struct str *buf, const char *title,
    const int want_graph_js);
void html_close(struct str *buf);

#endif
/* vim:set ts=3 sw=3 tw=78 expandtab: */
