/* darkstat 3
 * copyright (c) 2001-2011 Emil Mikulic.
 *
 * http.c: embedded webserver.
 * This borrows a lot of code from darkhttpd.
 *
 * You may use, modify and redistribute this file under the terms of the
 * GNU General Public License version 2. (see COPYING.GPL)
 */

#include "cdefs.h"
#include "config.h"
#include "conv.h"
#include "err.h"
#include "graph_db.h"
#include "hosts_db.h"
#include "http.h"
#include "now.h"
#include "queue.h"
#include "str.h"

#include <sys/uio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <zlib.h>

static const char mime_type_xml[] = "text/xml";
static const char mime_type_html[] = "text/html; charset=us-ascii";
static const char mime_type_css[] = "text/css";
static const char mime_type_js[] = "text/javascript";
static const char encoding_identity[] = "identity";
static const char encoding_gzip[] = "gzip";

static const char server[] = PACKAGE_NAME "/" PACKAGE_VERSION;
static int idletime = 60;
#define MAX_REQUEST_LENGTH 4000

static int *insocks = NULL;
static unsigned int insock_num = 0;

struct connection {
    LIST_ENTRY(connection) entries;

    int socket;
    struct sockaddr_storage client;
    time_t last_active;
    enum {
        RECV_REQUEST,          /* receiving request */
        SEND_HEADER_AND_REPLY, /* try to send header+reply together */
        SEND_HEADER,           /* sending generated header */
        SEND_REPLY,            /* sending reply */
        DONE                   /* conn closed, need to remove from queue */
        } state;

    /* char request[request_length+1] is null-terminated */
    char *request;
    size_t request_length;
    int accept_gzip;

    /* request fields */
    char *method, *uri, *query; /* query can be NULL */

    char *header;
    const char *mime_type, *encoding, *header_extra;
    size_t header_length, header_sent;
    int header_dont_free, header_only, http_code;

    char *reply;
    int reply_dont_free;
    size_t reply_length, reply_sent;

    unsigned int total_sent; /* header + body = total, for logging */
};

static LIST_HEAD(conn_list_head, connection) connlist =
    LIST_HEAD_INITIALIZER(conn_list_head);

struct bindaddr_entry {
    STAILQ_ENTRY(bindaddr_entry) entries;
    const char *s;
};
static STAILQ_HEAD(bindaddrs_head, bindaddr_entry) bindaddrs =
    STAILQ_HEAD_INITIALIZER(bindaddrs);

/* ---------------------------------------------------------------------------
 * Decode URL by converting %XX (where XX are hexadecimal digits) to the
 * character it represents.  Don't forget to free the return value.
 */
static char *urldecode(const char *url)
{
    size_t i, len = strlen(url);
    char *out = xmalloc(len+1);
    int pos;

    for (i=0, pos=0; i<len; i++)
    {
        if (url[i] == '%' && i+2 < len &&
            isxdigit(url[i+1]) && isxdigit(url[i+2]))
        {
            /* decode %XX */
            #define HEX_TO_DIGIT(hex) ( \
                ((hex) >= 'A' && (hex) <= 'F') ? ((hex)-'A'+10): \
                ((hex) >= 'a' && (hex) <= 'f') ? ((hex)-'a'+10): \
                ((hex)-'0') )

            out[pos++] = HEX_TO_DIGIT(url[i+1]) * 16 +
                         HEX_TO_DIGIT(url[i+2]);
            i += 2;

            #undef HEX_TO_DIGIT
        }
        else
        {
            /* straight copy */
            out[pos++] = url[i];
        }
    }
    out[pos] = 0;
#if 0
    /* don't really need to realloc here - it's probably a performance hit */
    out = xrealloc(out, strlen(out)+1);  /* dealloc what we don't need */
#endif
    return (out);
}



/* ---------------------------------------------------------------------------
 * Consolidate slashes in-place by shifting parts of the string over repeated
 * slashes.
 */
static void consolidate_slashes(char *s)
{
    size_t left = 0, right = 0;
    int saw_slash = 0;

    assert(s != NULL);

    while (s[right] != '\0')
    {
        if (saw_slash)
        {
            if (s[right] == '/') right++;
            else
            {
                saw_slash = 0;
                s[left++] = s[right++];
            }
        }
        else
        {
            if (s[right] == '/') saw_slash++;
            s[left++] = s[right++];
        }
    }
    s[left] = '\0';
}



/* ---------------------------------------------------------------------------
 * Resolve /./ and /../ in a URI, returing a new, safe URI, or NULL if the URI
 * is invalid/unsafe.  Returned buffer needs to be deallocated.
 */
static char *make_safe_uri(char *uri)
{
    char **elem, *out;
    unsigned int slashes = 0, elements = 0;
    size_t urilen, i, j, pos;

    assert(uri != NULL);
    if (uri[0] != '/')
        return (NULL);
    consolidate_slashes(uri);
    urilen = strlen(uri);

    /* count the slashes */
    for (i=0, slashes=0; i<urilen; i++)
        if (uri[i] == '/') slashes++;

    /* make an array for the URI elements */
    elem = xmalloc(sizeof(*elem) * slashes);
    for (i=0; i<slashes; i++)
        elem[i] = (NULL);

    /* split by slashes and build elem[] array */
    for (i=1; i<urilen;)
    {
        /* look for the next slash */
        for (j=i; j<urilen && uri[j] != '/'; j++)
            ;

        /* process uri[i,j) */
        if ((j == i+1) && (uri[i] == '.'))
            /* "." */;
        else if ((j == i+2) && (uri[i] == '.') && (uri[i+1] == '.'))
        {
            /* ".." */
            if (elements == 0)
            {
                /*
                 * Unsafe string so free elem[].  All its elements are free
                 * at this point.
                 */
                free(elem);
                return (NULL);
            }
            else
            {
                elements--;
                free(elem[elements]);
            }
        }
        else elem[elements++] = split_string(uri, i, j);

        i = j + 1; /* uri[j] is a slash - move along one */
    }

    /* reassemble */
    out = xmalloc(urilen+1); /* it won't expand */
    pos = 0;
    for (i=0; i<elements; i++)
    {
        size_t delta = strlen(elem[i]);

        assert(pos <= urilen);
        out[pos++] = '/';

        assert(pos+delta <= urilen);
        memcpy(out+pos, elem[i], delta);
        free(elem[i]);
        pos += delta;
    }
    free(elem);

    if ((elements == 0) || (uri[urilen-1] == '/')) out[pos++] = '/';
    assert(pos <= urilen);
    out[pos] = '\0';

#if 0
    /* don't really need to do this and it's probably a performance hit: */
    /* shorten buffer if necessary */
    if (pos != urilen) out = xrealloc(out, strlen(out)+1);
#endif
    return (out);
}

/* ---------------------------------------------------------------------------
 * Allocate and initialize an empty connection.
 */
static struct connection *new_connection(void)
{
    struct connection *conn = xmalloc(sizeof(*conn));

    conn->socket = -1;
    memset(&conn->client, 0, sizeof(conn->client));
    conn->last_active = now;
    conn->request = NULL;
    conn->request_length = 0;
    conn->accept_gzip = 0;
    conn->method = NULL;
    conn->uri = NULL;
    conn->query = NULL;
    conn->header = NULL;
    conn->mime_type = NULL;
    conn->encoding = NULL;
    conn->header_extra = "";
    conn->header_length = 0;
    conn->header_sent = 0;
    conn->header_dont_free = 0;
    conn->header_only = 0;
    conn->http_code = 0;
    conn->reply = NULL;
    conn->reply_dont_free = 0;
    conn->reply_length = 0;
    conn->reply_sent = 0;
    conn->total_sent = 0;

    /* Make it harmless so it gets garbage-collected if it should, for some
     * reason, fail to be correctly filled out.
     */
    conn->state = DONE;

    return (conn);
}



/* ---------------------------------------------------------------------------
 * Accept a connection from sockin and add it to the connection queue.
 */
static void accept_connection(const int sockin)
{
    struct sockaddr_storage addrin;
    socklen_t sin_size;
    struct connection *conn;
    char ipaddr[INET6_ADDRSTRLEN], portstr[12];
    int sock;

    sin_size = (socklen_t)sizeof(addrin);
    sock = accept(sockin, (struct sockaddr *)&addrin, &sin_size);
    if (sock == -1)
    {
        if (errno == ECONNABORTED || errno == EINTR)
        {
            verbosef("accept() failed: %s", strerror(errno));
            return;
        }
        /* else */ err(1, "accept()");
    }

    fd_set_nonblock(sock);

    /* allocate and initialise struct connection */
    conn = new_connection();
    conn->socket = sock;
    conn->state = RECV_REQUEST;
    memcpy(&conn->client, &addrin, sizeof(conn->client));
    LIST_INSERT_HEAD(&connlist, conn, entries);

    getnameinfo((struct sockaddr *) &addrin, sin_size,
            ipaddr, sizeof(ipaddr), portstr, sizeof(portstr),
            NI_NUMERICHOST | NI_NUMERICSERV);
    verbosef("accepted connection from %s:%s", ipaddr, portstr);
}



/* ---------------------------------------------------------------------------
 * Log a connection, then cleanly deallocate its internals.
 */
static void free_connection(struct connection *conn)
{
    dverbosef("free_connection(%d)", conn->socket);
    if (conn->socket != -1) close(conn->socket);
    if (conn->request != NULL) free(conn->request);
    if (conn->method != NULL) free(conn->method);
    if (conn->uri != NULL) free(conn->uri);
    if (conn->query != NULL) free(conn->query);
    if (conn->header != NULL && !conn->header_dont_free) free(conn->header);
    if (conn->reply != NULL && !conn->reply_dont_free) free(conn->reply);
}



/* ---------------------------------------------------------------------------
 * Format [when] as an RFC1123 date, stored in the specified buffer.  The same
 * buffer is returned for convenience.
 */
#define DATE_LEN 30 /* strlen("Fri, 28 Feb 2003 00:02:08 GMT")+1 */
static char *rfc1123_date(char *dest, const time_t when)
{
    time_t tmp = when;
    if (strftime(dest, DATE_LEN,
        "%a, %d %b %Y %H:%M:%S %Z", gmtime(&tmp) ) == 0)
            errx(1, "strftime() failed [%s]", dest);
    return (dest);
}

static void generate_header(struct connection *conn,
    const int code, const char *text)
{
    char date[DATE_LEN];

    assert(conn->header == NULL);
    assert(conn->mime_type != NULL);
    if (conn->encoding == NULL)
        conn->encoding = encoding_identity;

    verbosef("http: %d %s (%s: %d bytes)", code, text,
        conn->encoding, conn->reply_length);
    conn->header_length = xasprintf(&(conn->header),
        "HTTP/1.1 %d %s\r\n"
        "Date: %s\r\n"
        "Server: %s\r\n"
        "Vary: Accept-Encoding\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %d\r\n"
        "Content-Encoding: %s\r\n"
        "X-Robots-Tag: noindex, noarchive\r\n"
        "%s"
        "\r\n"
        ,
        code, text,
        rfc1123_date(date, now), server,
        conn->mime_type, conn->reply_length, conn->encoding,
        conn->header_extra);
    conn->http_code = code;
}



/* ---------------------------------------------------------------------------
 * A default reply for any (erroneous) occasion.
 */
static void default_reply(struct connection *conn,
    const int errcode, const char *errname, const char *format, ...)
{
    char *reason;
    va_list va;

    va_start(va, format);
    xvasprintf(&reason, format, va);
    va_end(va);

    conn->reply_length = xasprintf(&(conn->reply),
     "<html><head><title>%d %s</title></head><body>\n"
     "<h1>%s</h1>\n" /* errname */
     "%s\n" /* reason */
     "<hr>\n"
     "Generated by %s"
     "</body></html>\n",
     errcode, errname, errname, reason, server);
    free(reason);

    /* forget any dangling metadata */
    conn->mime_type = mime_type_html;
    conn->encoding = encoding_identity;

    generate_header(conn, errcode, errname);
}



/* ---------------------------------------------------------------------------
 * Parses a single HTTP request field.  Returns string from end of [field] to
 * first \r, \n or end of request string.  Returns NULL if [field] can't be
 * matched.
 *
 * You need to remember to deallocate the result.
 * example: parse_field(conn, "Referer: ");
 */
static char *parse_field(const struct connection *conn, const char *field)
{
    size_t bound1, bound2;
    char *pos;

    /* find start */
    pos = strstr(conn->request, field);
    if (pos == NULL)
        return (NULL);
    bound1 = pos - conn->request + strlen(field);

    /* find end */
    for (bound2 = bound1;
        conn->request[bound2] != '\r' &&
        bound2 < conn->request_length; bound2++)
            ;

    /* copy to buffer */
    return (split_string(conn->request, bound1, bound2));
}



/* ---------------------------------------------------------------------------
 * Parse an HTTP request like "GET /hosts/?sort=in HTTP/1.1" to get the method
 * (GET), the uri (/hosts/), the query (sort=in) and whether the UA will
 * accept gzip encoding.  Remember to deallocate all these buffers.  Query
 * can be NULL.  The method will be returned in uppercase.
 */
static int parse_request(struct connection *conn)
{
    size_t bound1, bound2, mid;
    char *accept_enc;

    /* parse method */
    for (bound1 = 0; bound1 < conn->request_length &&
        conn->request[bound1] != ' '; bound1++)
            ;

    conn->method = split_string(conn->request, 0, bound1);
    strntoupper(conn->method, bound1);

    /* parse uri */
    for (; bound1 < conn->request_length &&
        conn->request[bound1] == ' '; bound1++)
            ;

    if (bound1 == conn->request_length)
        return (0); /* fail */

    for (bound2=bound1+1; bound2 < conn->request_length &&
        conn->request[bound2] != ' ' &&
        conn->request[bound2] != '\r'; bound2++)
            ;

    /* find query string */
    for (mid=bound1; mid<bound2 && conn->request[mid] != '?'; mid++)
        ;

    if (conn->request[mid] == '?') {
        conn->query = split_string(conn->request, mid+1, bound2);
        bound2 = mid;
    }

    conn->uri = split_string(conn->request, bound1, bound2);

    /* parse important fields */
    accept_enc = parse_field(conn, "Accept-Encoding: ");
    if (accept_enc != NULL) {
        if (strstr(accept_enc, "gzip") != NULL)
            conn->accept_gzip = 1;
        free(accept_enc);
    }
    return (1);
}

/* FIXME: maybe we need a smarter way of doing static pages: */

/* ---------------------------------------------------------------------------
 * Web interface: static stylesheet.
 */
static void
static_style_css(struct connection *conn)
{
#include "stylecss.h"

    conn->reply = style_css;
    conn->reply_length = style_css_len;
    conn->reply_dont_free = 1;
    conn->mime_type = mime_type_css;
}

/* ---------------------------------------------------------------------------
 * Web interface: static JavaScript.
 */
static void
static_graph_js(struct connection *conn)
{
#include "graphjs.h"

    conn->reply = graph_js;
    conn->reply_length = graph_js_len;
    conn->reply_dont_free = 1;
    conn->mime_type = mime_type_js;
}

/* ---------------------------------------------------------------------------
 * gzip a reply, if requested and possible.  Don't bother with a minimum
 * length requirement, I've never seen a page fail to compress.
 */
static void
process_gzip(struct connection *conn)
{
    char *buf;
    size_t len;
    z_stream zs;

    if (!conn->accept_gzip)
        return;

    buf = xmalloc(conn->reply_length);
    len = conn->reply_length;

    zs.zalloc = Z_NULL;
    zs.zfree = Z_NULL;
    zs.opaque = Z_NULL;

    if (deflateInit2(&zs, Z_BEST_COMPRESSION, Z_DEFLATED,
        15+16, /* 15 = biggest window, 16 = add gzip header+trailer */
        8 /* default */,
        Z_DEFAULT_STRATEGY) != Z_OK)
       return;

    zs.avail_in = conn->reply_length;
    zs.next_in = (unsigned char *)conn->reply;

    zs.avail_out = conn->reply_length;
    zs.next_out = (unsigned char *)buf;

    if (deflate(&zs, Z_FINISH) != Z_STREAM_END) {
        deflateEnd(&zs);
        free(buf);
        verbosef("failed to compress %u bytes", (unsigned int)len);
        return;
    }

    if (conn->reply_dont_free)
        conn->reply_dont_free = 0;
    else
        free(conn->reply);

    conn->reply = buf;
    conn->reply_length -= zs.avail_out;
    conn->encoding = encoding_gzip;
    deflateEnd(&zs);
}

/* ---------------------------------------------------------------------------
 * Process a GET/HEAD request
 */
static void process_get(struct connection *conn)
{
    char *decoded_url, *safe_url;

    verbosef("http: %s \"%s\" %s", conn->method, conn->uri,
        (conn->query == NULL)?"":conn->query);

    /* work out path of file being requested */
    decoded_url = urldecode(conn->uri);

    /* make sure it's safe */
    safe_url = make_safe_uri(decoded_url);
    free(decoded_url);
    if (safe_url == NULL)
    {
        default_reply(conn, 400, "Bad Request",
                "You requested an invalid URI: %s", conn->uri);
        return;
    }

    if (strcmp(safe_url, "/") == 0) {
        struct str *buf = html_front_page();
        str_extract(buf, &(conn->reply_length), &(conn->reply));
        conn->mime_type = mime_type_html;
    }
    else if (str_starts_with(safe_url, "/hosts/")) {
        /* FIXME here - make this saner */
        struct str *buf = html_hosts(safe_url, conn->query);
        if (buf == NULL) {
            default_reply(conn, 404, "Not Found",
                "The page you requested could not be found.");
            free(safe_url);
            return;
        }
        str_extract(buf, &(conn->reply_length), &(conn->reply));
        conn->mime_type = mime_type_html;
    }
    else if (str_starts_with(safe_url, "/graphs.xml")) {
        struct str *buf = xml_graphs();
        str_extract(buf, &(conn->reply_length), &(conn->reply));
        conn->mime_type = mime_type_xml;
        /* hack around Opera caching the XML */
        conn->header_extra = "Pragma: no-cache\r\n";
    }
    else if (strcmp(safe_url, "/style.css") == 0)
        static_style_css(conn);
    else if (strcmp(safe_url, "/graph.js") == 0)
        static_graph_js(conn);
    else {
        default_reply(conn, 404, "Not Found",
            "The page you requested could not be found.");
        free(safe_url);
        return;
    }
    free(safe_url);

    process_gzip(conn);
    assert(conn->mime_type != NULL);
    generate_header(conn, 200, "OK");
}



/* ---------------------------------------------------------------------------
 * Process a request: build the header and reply, advance state.
 */
static void process_request(struct connection *conn)
{
    if (!parse_request(conn))
    {
        default_reply(conn, 400, "Bad Request",
            "You sent a request that the server couldn't understand.");
    }
    else if (strcmp(conn->method, "GET") == 0)
    {
        process_get(conn);
    }
    else if (strcmp(conn->method, "HEAD") == 0)
    {
        process_get(conn);
        conn->header_only = 1;
    }
    else
    {
        default_reply(conn, 501, "Not Implemented",
            "The method you specified (%s) is not implemented.",
            conn->method);
    }

    /* advance state */
    if (conn->header_only)
        conn->state = SEND_HEADER;
    else
        conn->state = SEND_HEADER_AND_REPLY;

    /* request not needed anymore */
    free(conn->request);
    conn->request = NULL; /* important: don't free it again later */
}



/* ---------------------------------------------------------------------------
 * Receiving request.
 */
static void poll_recv_request(struct connection *conn)
{
    #define BUFSIZE 65536
    char buf[BUFSIZE];
    ssize_t recvd;

    recvd = recv(conn->socket, buf, BUFSIZE, 0);
    dverbosef("poll_recv_request(%d) got %d bytes", conn->socket, (int)recvd);
    if (recvd <= 0)
    {
        if (recvd == -1)
            verbosef("recv(%d) error: %s", conn->socket, strerror(errno));
        conn->state = DONE;
        return;
    }
    conn->last_active = now;
    #undef BUFSIZE

    /* append to conn->request */
    conn->request = xrealloc(conn->request, conn->request_length+recvd+1);
    memcpy(conn->request+conn->request_length, buf, (size_t)recvd);
    conn->request_length += recvd;
    conn->request[conn->request_length] = 0;

    /* process request if we have all of it */
    if (conn->request_length > 4 &&
        memcmp(conn->request+conn->request_length-4, "\r\n\r\n", 4) == 0)
        process_request(conn);

    /* die if it's too long */
    if (conn->request_length > MAX_REQUEST_LENGTH)
    {
        default_reply(conn, 413, "Request Entity Too Large",
            "Your request was dropped because it was too long.");
        conn->state = SEND_HEADER;
    }
}



/* ---------------------------------------------------------------------------
 * Try to send header and [a part of the] reply in one packet.
 */
static void poll_send_header_and_reply(struct connection *conn)
{
    ssize_t sent;
    struct iovec iov[2];

    assert(!conn->header_only);
    assert(conn->reply_length > 0);
    assert(conn->header_sent == 0);

    assert(conn->reply_sent == 0);

    /* Fill out iovec */
    iov[0].iov_base = conn->header;
    iov[0].iov_len = conn->header_length;

    iov[1].iov_base = conn->reply;
    iov[1].iov_len = conn->reply_length;

    sent = writev(conn->socket, iov, 2);
    conn->last_active = now;

    /* handle any errors (-1) or closure (0) in send() */
    if (sent < 1) {
        if (sent == -1)
            verbosef("writev(%d) error: %s", conn->socket, strerror(errno));
        conn->state = DONE;
        return;
    }

    /* Figure out what we've sent. */
    conn->total_sent += (unsigned int)sent;
    if (sent < (ssize_t)conn->header_length) {
        verbosef("partially sent header");
        conn->header_sent = sent;
        conn->state = SEND_HEADER;
        return;
    }
    /* else */
    conn->header_sent = conn->header_length;
    sent -= conn->header_length;

    if (sent < (ssize_t)conn->reply_length) {
        verbosef("partially sent reply");
        conn->reply_sent += sent;
        conn->state = SEND_REPLY;
        return;
    }
    /* else */
    conn->reply_sent = conn->reply_length;
    conn->state = DONE;
}

/* ---------------------------------------------------------------------------
 * Sending header.  Assumes conn->header is not NULL.
 */
static void poll_send_header(struct connection *conn)
{
    ssize_t sent;

    sent = send(conn->socket, conn->header + conn->header_sent,
        conn->header_length - conn->header_sent, 0);
    conn->last_active = now;
    dverbosef("poll_send_header(%d) sent %d bytes", conn->socket, (int)sent);

    /* handle any errors (-1) or closure (0) in send() */
    if (sent < 1)
    {
        if (sent == -1)
            verbosef("send(%d) error: %s", conn->socket, strerror(errno));
        conn->state = DONE;
        return;
    }
    conn->header_sent += (unsigned int)sent;
    conn->total_sent += (unsigned int)sent;

    /* check if we're done sending */
    if (conn->header_sent == conn->header_length)
    {
        if (conn->header_only)
            conn->state = DONE;
        else
            conn->state = SEND_REPLY;
    }
}



/* ---------------------------------------------------------------------------
 * Sending reply.
 */
static void poll_send_reply(struct connection *conn)
{
    ssize_t sent;

    sent = send(conn->socket,
        conn->reply + conn->reply_sent,
        conn->reply_length - conn->reply_sent, 0);
    conn->last_active = now;
    dverbosef("poll_send_reply(%d) sent %d: [%d-%d] of %d",
        conn->socket, (int)sent,
        (int)conn->reply_sent,
        (int)(conn->reply_sent + sent - 1),
        (int)conn->reply_length);

    /* handle any errors (-1) or closure (0) in send() */
    if (sent < 1)
    {
        if (sent == -1)
            verbosef("send(%d) error: %s", conn->socket, strerror(errno));
        else if (sent == 0)
            verbosef("send(%d) closure", conn->socket);
        conn->state = DONE;
        return;
    }
    conn->reply_sent += (unsigned int)sent;
    conn->total_sent += (unsigned int)sent;

    /* check if we're done sending */
    if (conn->reply_sent == conn->reply_length) conn->state = DONE;
}

/* Use getaddrinfo to figure out what type of socket to create and
 * what to bind it to.  "bindaddr" can be NULL.  Remember to freeaddrinfo()
 * the result.
 */
static struct addrinfo *get_bind_addr(
    const char *bindaddr, const unsigned short bindport)
{
    struct addrinfo hints, *ai;
    char portstr[6];
    int ret;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
#ifdef linux
    /* Special case for Linux: with bindaddr=NULL and ai_family=AF_UNSPEC,
     * we successfully bind to 0.0.0.0 and then fail to bind to ::, resulting
     * in a v4-only http socket.
     *
     * Conversely, if we specify AF_INET6, we bind to just :: which is able to
     * accept v4 as well as v6 connections.
     */
    if (bindaddr == NULL)
        hints.ai_family = AF_INET6; /* we'll get a dual stack socket */
#endif
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    snprintf(portstr, sizeof(portstr), "%u", bindport);
    if ((ret = getaddrinfo(bindaddr, portstr, &hints, &ai)))
        err(1, "getaddrinfo(%s,%s) failed: %s",
            bindaddr ? bindaddr : "NULL", portstr, gai_strerror(ret));
    if (ai == NULL)
        err(1, "getaddrinfo() returned NULL pointer");
    return ai;
}

void http_add_bindaddr(const char *bindaddr)
{
    struct bindaddr_entry *ent;

    ent = xmalloc(sizeof(*ent));
    ent->s = bindaddr;
    STAILQ_INSERT_TAIL(&bindaddrs, ent, entries);
}

static void http_listen_one(struct addrinfo *ai,
    const unsigned short bindport)
{
    char ipaddr[INET6_ADDRSTRLEN];
    int sockin, sockopt, ret;

    /* create incoming socket */
    if ((sockin = socket(ai->ai_family, SOCK_STREAM, 0)) == -1)
        err(1, "socket() failed");

    /* reuse address */
    sockopt = 1;
    if (setsockopt(sockin, SOL_SOCKET, SO_REUSEADDR,
            &sockopt, sizeof(sockopt)) == -1)
        err(1, "can't set SO_REUSEADDR");

    /* format address into ipaddr string */
    if ((ret = getnameinfo(ai->ai_addr, ai->ai_addrlen, ipaddr,
                           sizeof(ipaddr), NULL, 0, NI_NUMERICHOST)) != 0)
        err(1, "getnameinfo failed: %s", gai_strerror(ret));

    /* bind socket */
    if (bind(sockin, ai->ai_addr, ai->ai_addrlen) == -1)
        err(1, "bind(\"%s\") failed", ipaddr);

    /* listen on socket */
    if (listen(sockin, -1) == -1)
        err(1, "listen() failed");

    verbosef("listening on http://%s%s%s:%u/",
        (ai->ai_family == AF_INET6) ? "[" : "",
        ipaddr,
        (ai->ai_family == AF_INET6) ? "]" : "",
        bindport);

    /* add to insocks */
    insocks = xrealloc(insocks, sizeof(*insocks) * (insock_num + 1));
    insocks[insock_num++] = sockin;
}

/* Initialize the http sockets and listen on them. */
void http_listen(const unsigned short bindport)
{
    /* If the user didn't specify any bind addresses, add a NULL.
     * This will become a wildcard.
     */
    if (STAILQ_EMPTY(&bindaddrs))
        http_add_bindaddr(NULL);

    /* Listen on every specified interface. */
    while (!STAILQ_EMPTY(&bindaddrs)) {
        struct bindaddr_entry *bindaddr = STAILQ_FIRST(&bindaddrs);
        struct addrinfo *ai, *ais = get_bind_addr(bindaddr->s, bindport);

        /* There could be multiple addresses returned, handle them all. */
        for (ai = ais; ai; ai = ai->ai_next)
            http_listen_one(ai, bindport);

        freeaddrinfo(ais);

        STAILQ_REMOVE_HEAD(&bindaddrs, entries);
        free(bindaddr);
    }

    /* ignore SIGPIPE */
    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR)
        err(1, "can't ignore SIGPIPE");
}



/* ---------------------------------------------------------------------------
 * Set recv/send fd_sets and calculate timeout length.
 */
void
http_fd_set(fd_set *recv_set, fd_set *send_set, int *max_fd,
    struct timeval *timeout, int *need_timeout)
{
    struct connection *conn, *next;
    int minidle = idletime + 1;
    unsigned int i;

    #define MAX_FD_SET(sock, fdset) do { \
        FD_SET(sock, fdset); *max_fd = MAX(*max_fd, sock); } while(0)

    for (i=0; i<insock_num; i++)
        MAX_FD_SET(insocks[i], recv_set);

    LIST_FOREACH_SAFE(conn, &connlist, entries, next)
    {
        int idlefor = now - conn->last_active;

        /* Time out dead connections. */
        if (idlefor >= idletime) {
            char ipaddr[INET6_ADDRSTRLEN];
            /* FIXME: this is too late on FreeBSD, socket is invalid */
            int ret = getnameinfo((struct sockaddr *)&conn->client,
                sizeof(conn->client), ipaddr, sizeof(ipaddr),
                NULL, 0, NI_NUMERICHOST);
            if (ret == 0)
                verbosef("http socket timeout from %s (fd %d)",
                        ipaddr, conn->socket);
            else
                warn("http socket timeout: getnameinfo error: %s",
                    gai_strerror(ret));
            conn->state = DONE;
        }

        /* Connections that need a timeout. */
        if (conn->state != DONE)
            minidle = MIN(minidle, (idletime - idlefor));

        switch (conn->state)
        {
        case DONE:
            /* clean out stale connection */
            LIST_REMOVE(conn, entries);
            free_connection(conn);
            free(conn);
            break;

        case RECV_REQUEST:
            MAX_FD_SET(conn->socket, recv_set);
            break;

        case SEND_HEADER_AND_REPLY:
        case SEND_HEADER:
        case SEND_REPLY:
            MAX_FD_SET(conn->socket, send_set);
            break;

        default: errx(1, "invalid state");
        }
    }
    #undef MAX_FD_SET

    /* Only set timeout if cap hasn't already. */
    if ((*need_timeout == 0) && (minidle <= idletime)) {
        *need_timeout = 1;
        timeout->tv_sec = minidle;
        timeout->tv_usec = 0;
    }
}



/* ---------------------------------------------------------------------------
 * poll connections that select() says need attention
 */
void http_poll(fd_set *recv_set, fd_set *send_set)
{
    struct connection *conn;
    unsigned int i;

    for (i=0; i<insock_num; i++)
        if (FD_ISSET(insocks[i], recv_set))
            accept_connection(insocks[i]);

    LIST_FOREACH(conn, &connlist, entries)
    switch (conn->state)
    {
    case RECV_REQUEST:
        if (FD_ISSET(conn->socket, recv_set)) poll_recv_request(conn);
        break;

    case SEND_HEADER_AND_REPLY:
        if (FD_ISSET(conn->socket, send_set)) poll_send_header_and_reply(conn);
        break;

    case SEND_HEADER:
        if (FD_ISSET(conn->socket, send_set)) poll_send_header(conn);
        break;

    case SEND_REPLY:
        if (FD_ISSET(conn->socket, send_set)) poll_send_reply(conn);
        break;

    case DONE: /* fallthrough */
    default: errx(1, "invalid state");
    }
}

void http_stop(void) {
    struct connection *conn;
    unsigned int i;

    /* Close listening sockets. */
    for (i=0; i<insock_num; i++)
        close(insocks[i]);
    free(insocks);
    insocks = NULL;

    /* Close in-flight connections. */
    LIST_FOREACH(conn, &connlist, entries) {
        LIST_REMOVE(conn, entries);
        free_connection(conn);
        free(conn);
    }
}

/* vim:set ts=4 sw=4 et tw=78: */
