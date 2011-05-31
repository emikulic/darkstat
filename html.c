/* darkstat 3
 *
 * html.c: HTML header/footer templating for web interface.
 * copyright (c) 2006 Ben Stewart.
 * copyright (c) 2010 Malte S. Stretz.
 *
 * You may use, modify and redistribute this file under the terms of the
 * GNU General Public License version 2. (see COPYING.GPL)
 */

#include "darkstat.h"
#include "str.h"
#include "html.h"
#include "http.h" /* for http_base_url */

void html_open(struct str *buf, const char *title,
    const int want_graph_js)
{
    str_appendf(buf,
        "<!DOCTYPE html>\n"
        "<html>\n"
        "<head>\n"
         "<title>%s (darkstat3 %s)</title>\n"
         "<meta name=\"generator\" content=\"" PACKAGE_STRING "\">\n"
         "<meta name=\"robots\" content=\"noindex, noarchive\">\n"
         "<link rel=\"stylesheet\" href=\"%sstyle.css\" type=\"text/css\">\n"
        , title, opt_interface, http_base_url);

    if (want_graph_js)
        str_appendf(buf,
            "<script src=\"%sgraph.js\" type=\"text/javascript\"></script>\n"
            , http_base_url);

    str_appendf(buf,
        "</head>\n"
        "<body>\n"
        "<div class=\"menu\">\n"
        "<ul class=\"menu\">" /* no whitespace (newlines) in list */
         "<li class=\"label\">" PACKAGE_STRING "</li>"
         "<li><a href=\"%s\">graphs</a></li>"
         "<li><a href=\"%shosts/\">hosts</a></li>"
         "<li><a href=\"" PACKAGE_URL "\">homepage</a></li>"
        "</ul>\n"
        "</div>\n"
        "<div class=\"content\">\n"
         "<h2 class=\"pageheader\">%s</h2>\n"
        , http_base_url, http_base_url, title);
}

void html_close(struct str *buf)
{
    str_append(buf, 
        "</div>\n"
        "</body>\n"
        "</html>\n");
}

/* vim:set ts=4 sw=4 tw=78 expandtab: */
