/* darkstat 3
 *
 * html.c: HTML header/footer templating for web interface.
 * copyright (c) 2006 Ben Stewart.
 * copyright (c) 2010 Malte S. Stretz.
 *
 * You may use, modify and redistribute this file under the terms of the
 * GNU General Public License version 2. (see COPYING.GPL)
 */

#include "config.h"
#include "str.h"
#include "html.h"
#include "opt.h"

#include <assert.h>

static const char *relpaths[] = {
    ".",
    "..",
    "../.."
};

void html_open(struct str *buf, const char *title,
    const unsigned int path_depth, const int want_graph_js)
{
    const char *root;
    assert(path_depth < (sizeof(relpaths)/sizeof(*relpaths)));
    root = relpaths[path_depth];

    str_appendf(buf,
        "<!DOCTYPE html>\n"
        "<html>\n"
        "<head>\n"
         "<title>%s (darkstat %s)</title>\n"
         "<meta name=\"generator\" content=\"" PACKAGE_STRING "\">\n"
         "<meta name=\"robots\" content=\"noindex, noarchive\">\n"
         "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no\">\n"
         "<link rel=\"stylesheet\" href=\"%s/style.css\" type=\"text/css\">\n",
        title, title_interfaces, root);

    if (want_graph_js)
        str_appendf(buf,
            "<script src=\"%s/graph.js\" type=\"text/javascript\"></script>\n"
            , root);

    str_appendf(buf,
        "</head>\n"
        "<body>\n"
        "<div class=\"menu\">\n"
        "<ul class=\"menu\">" /* no whitespace (newlines) in list */
         "<li class=\"label\">" PACKAGE_STRING "</li>"
         "<li><a href=\"%s/\">graphs</a></li>"
         "<li><a href=\"%s/hosts/\">hosts</a></li>"
         "<li><a href=\"" PACKAGE_URL "\">homepage</a></li>"
        "</ul>\n"
        "</div>\n"
        "<div class=\"content\">\n"
         "<h2 class=\"pageheader\">%s</h2>\n"
        , root, root, title);
}

void html_close(struct str *buf)
{
    str_append(buf, 
        "</div>\n"
        "</body>\n"
        "</html>\n");
}

/* vim:set ts=4 sw=4 tw=80 et: */
