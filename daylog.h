/* darkstat 3
 * copyright (c) 2007 Emil Mikulic.
 *
 * daylog.h: daily usage log
 */

#include "graph_db.h" /* for graph_dir */

void daylog_init(const char *filename);
void daylog_free(void);
void daylog_acct(uint64_t amount, enum graph_dir dir);

/* vim:set ts=3 sw=3 tw=78 et: */
