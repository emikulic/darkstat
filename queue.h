/* This is a stripped down version of FreeBSD's
 * src/sys/sys/queue.h,v 1.60.2.1
 *
 * The original file's license:
 * 
 * Copyright (c) 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#define	STAILQ_HEAD(name, type)						\
struct name {								\
	struct type *stqh_first;/* first element */			\
	struct type **stqh_last;/* addr of last next element */		\
}

#define	STAILQ_HEAD_INITIALIZER(head)					\
	{ NULL, &(head).stqh_first }

#define	STAILQ_ENTRY(type)						\
struct {								\
	struct type *stqe_next;	/* next element */			\
}

#define	STAILQ_EMPTY(head)	((head)->stqh_first == NULL)

#define	STAILQ_FIRST(head)	((head)->stqh_first)

#define STAILQ_FOREACH(var, head, field)                                \
        for((var) = STAILQ_FIRST((head));                               \
           (var);                                                       \
           (var) = STAILQ_NEXT((var), field))

#define	STAILQ_NEXT(elm, field)	((elm)->field.stqe_next)

#ifdef STAILQ_INSERT_TAIL
#undef STAILQ_INSERT_TAIL
#endif

#define	STAILQ_INSERT_TAIL(head, elm, field) do {			\
	STAILQ_NEXT((elm), field) = NULL;				\
	*(head)->stqh_last = (elm);					\
	(head)->stqh_last = &STAILQ_NEXT((elm), field);			\
} while (0)

#ifdef STAILQ_REMOVE_HEAD
#undef STAILQ_REMOVE_HEAD
#endif

#define	STAILQ_REMOVE_HEAD(head, field) do {				\
	if ((STAILQ_FIRST((head)) =					\
	     STAILQ_NEXT(STAILQ_FIRST((head)), field)) == NULL)		\
		(head)->stqh_last = &STAILQ_FIRST((head));		\
} while (0)

#undef LIST_HEAD
#define LIST_HEAD(name, type)                                           \
struct name {                                                           \
        struct type *lh_first;  /* first element */                     \
}

#undef LIST_HEAD_INITIALIZER
#define LIST_HEAD_INITIALIZER(head)                                     \
        { NULL }

#undef LIST_ENTRY
#define LIST_ENTRY(type)                                                \
struct {                                                                \
        struct type *le_next;   /* next element */                      \
        struct type **le_prev;  /* address of previous next element */  \
}

#undef LIST_FIRST
#define LIST_FIRST(head)        ((head)->lh_first)

#undef LIST_FOREACH
#define LIST_FOREACH(var, head, field)                                  \
        for ((var) = LIST_FIRST((head));                                \
            (var);                                                      \
            (var) = LIST_NEXT((var), field))

#undef LIST_FOREACH_SAFE
#define LIST_FOREACH_SAFE(var, head, field, tvar)                       \
    for ((var) = LIST_FIRST((head));                                    \
        (var) && ((tvar) = LIST_NEXT((var), field), 1);                 \
        (var) = (tvar))

#undef LIST_INIT
#define LIST_INIT(head) do {                                            \
        LIST_FIRST((head)) = NULL;                                      \
} while (0)

#undef LIST_INSERT_HEAD
#define LIST_INSERT_HEAD(head, elm, field) do {                         \
        if ((LIST_NEXT((elm), field) = LIST_FIRST((head))) != NULL)     \
                LIST_FIRST((head))->field.le_prev = &LIST_NEXT((elm), field);\
        LIST_FIRST((head)) = (elm);                                     \
        (elm)->field.le_prev = &LIST_FIRST((head));                     \
} while (0)

#undef LIST_NEXT
#define LIST_NEXT(elm, field)   ((elm)->field.le_next)

#undef LIST_REMOVE
#define LIST_REMOVE(elm, field) do {                                    \
        if (LIST_NEXT((elm), field) != NULL)                            \
                LIST_NEXT((elm), field)->field.le_prev =                \
                    (elm)->field.le_prev;                               \
        *(elm)->field.le_prev = LIST_NEXT((elm), field);                \
} while (0)
