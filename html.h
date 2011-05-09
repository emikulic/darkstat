/* darkstat 3
 *
 * html.h: HTML header/footer for web interface.
 * copyright (c) 2006 Ben Stewart.
 *
 * You may use, modify and redistribute this file under the terms of the
 * GNU General Public License version 2. (see COPYING.GPL)
 */
#ifndef __DARKSTAT_HTML_H
#define __DARKSTAT_HTML_H

#include "config.h" /* for PACKAGE_STRING */

static const char html_header_1[] =
"<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Strict//EN\"\n"
"  \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd\">\n"
"<html xmlns=\"http://www.w3.org/1999/xhtml\">\n"
"<head>\n"
" <link rel=\"stylesheet\" href=\"/style.css\" type=\"text/css\"/>\n";

static const char html_header_2[] =
"</head>\n"
"<body>\n"
"<div class=\"menu\">\n"
 "<ul class=\"menu\">\n"
  "<li class=\"label\">" PACKAGE_STRING "</li>"
  "<li><a href=\"/\">graphs</a></li>"
  "<li><a href=\"/hosts/\">hosts</a></li>"
  "<li><a href=\"http://dmr.ath.cx/net/darkstat/\">homepage</a></li>"
 "</ul>\n"
"</div>\n"
"<div class=\"content\">\n";

static const char html_footer[] =
"</div>\n"
"</body>\n"
"</html>\n";

#endif
/* vim:set ts=3 sw=3 tw=78 expandtab: */
