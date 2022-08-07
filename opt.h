/* darkstat 3
 * copyright (c) 2001-2012 Emil Mikulic.
 *
 * opt.h: global options
 */

/* Capture options. */
extern int opt_want_pppoe;
extern int opt_want_macs;
extern int opt_want_hexdump;
extern int opt_want_snaplen;
extern int opt_wait_secs;
extern int opt_want_peers;
extern int opt_want_ports;

/* Error/logging options. */
extern int opt_want_verbose;
extern int opt_want_syslog;

/* Accounting options. */
extern unsigned int opt_highest_port;
extern int opt_want_local_only;

/* Hosts table reduction - when the number of entries is about to exceed
 * <max>, we reduce the table to the top <keep> entries.
 */
extern unsigned int opt_hosts_max;
extern unsigned int opt_hosts_keep;
extern unsigned int opt_ports_max;
extern unsigned int opt_ports_keep;
extern unsigned int opt_peers_max;
extern unsigned int opt_peers_keep;

/* Hosts output options. */
extern int opt_want_lastseen;

/* Initialized in cap.c, added to <title> */
extern char *title_interfaces;

/* vim:set ts=3 sw=3 tw=78 expandtab: */
