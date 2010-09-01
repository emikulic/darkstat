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
#include "http.h"


void html_open(struct str *buf, const char *title, const char *interface,
    void (*header_callback)(struct str *buf))
{
    str_append(buf, "<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Strict//EN\"\n"
        "  \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd\">\n"
        "<html xmlns=\"http://www.w3.org/1999/xhtml\">\n"
        "<head>\n");
    str_appendf(buf, "<title>%s (darkstat3 : %s)</title>\n"
        "<meta name=\"generator\" content=\"%s\" />\n", title, interface,
        PACKAGE_STRING);
    str_appendf(buf, "<link rel=\"stylesheet\" href=\"%s%s\" type=\"text/css\"/>\n",
        base_url, "style.css");
    if (header_callback != NULL)
        header_callback(buf);
            
    str_append(buf, "</head>\n"
        "<body>\n"
        "<div class=\"menu\">\n"
        "<ul class=\"menu\">\n");
    str_appendf(buf, "<li class=\"label\">%s</li>\n"
        "<li><a href=\"%s\">graphs</a></li>\n"
        "<li><a href=\"%shosts/\">hosts</a></li>\n"
        "<li><a href=\"http://dmr.ath.cx/net/darkstat/\">homepage</a></li>\n",
        PACKAGE_STRING, base_url, base_url);
    str_append(buf, "</ul>\n"
        "</div>\n"
        "<div class=\"content\">\n");
    str_appendf(buf, "<h2 class=\"pageheader\">%s</h2>\n", title);
}

void html_close(struct str *buf)
{
    str_append(buf, 
        "</div>\n"
        "</body>\n"
        "</html>\n"
    );
}


/* vim:set ts=4 sw=4 tw=78 expandtab: */
