/* darkstat 3
 * copyright (c) 2001-2012 Emil Mikulic.
 *
 * hosts_sort.c: quicksort a table of buckets.
 *
 * You may use, modify and redistribute this file under the terms of the
 * GNU General Public License version 2. (see COPYING.GPL)
 */

#include "cdefs.h"
#include "err.h"
#include "hosts_db.h"

static int cmp_u64(const uint64_t a, const uint64_t b) {
   if (a < b) return (1);
   if (a > b) return (-1);
   return (0);
}

static int cmp_i64(const int64_t a, const int64_t b) {
   if (a < b) return (1);
   if (a > b) return (-1);
   return (0);
}

/* Comparator for sorting 'struct bucket' */
static int cmp(const struct bucket * const *x, const struct bucket * const *y,
    const enum sort_dir dir) {
   switch (dir) {
      case IN:
         return cmp_u64((*x)->in, (*y)->in);
      case OUT:
         return cmp_u64((*x)->out, (*y)->out);
      case TOTAL:
         return cmp_u64((*x)->total, (*y)->total);
      case LASTSEEN:
         return cmp_i64((*x)->u.host.last_seen_mono,
                        (*y)->u.host.last_seen_mono);
      default:
         errx(1, "cmp: unknown direction: %d", dir);
   }
}

/*
 * The quicksort code is derived from FreeBSD's
 * src/lib/libc/stdlib/qsort.c v1.12
 */

/*-
 * Copyright (c) 1992, 1993
 *     The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *     This product includes software developed by the University of
 *     California, Berkeley and its contributors.
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

static void
vecswap(const struct bucket **pi, const struct bucket **pj, int n)
{
   if (n <= 0)
      return;

   do {
      const struct bucket *t = *pi;
      *pi++ = *pj;
      *pj++ = t;
   } while (--n > 0);
}

#define swap(a, b) { \
   const struct bucket *t = *(const struct bucket **)(a); \
   *(const struct bucket **)(a) = *(const struct bucket **)(b); \
   *(const struct bucket **)(b) = t; \
}

static const struct bucket **
med3(const struct bucket **a,
     const struct bucket **b,
     const struct bucket **c,
     const enum sort_dir dir)
{
   return (cmp(a, b, dir) < 0)
    ? (cmp(b, c, dir) < 0 ? b : (cmp(a, c, dir) < 0 ? c : a ))
    : (cmp(b, c, dir) > 0 ? b : (cmp(a, c, dir) < 0 ? a : c ));
}

/* Partial sort - only sort elements in the range [left:right] */
void
qsort_buckets(const struct bucket **a, size_t n,
   size_t left, size_t right,
   const enum sort_dir dir)
{
	const struct bucket **pa, **pb, **pc, **pd, **pl, **pm, **pn;
	int d, r, swap_cnt;

loop:
	swap_cnt = 0;
	if (n < 7) {
		for (pm = a+1; pm < a+n; pm++)
			for (pl = pm;
			     (pl > a) && (cmp(pl-1, pl, dir) > 0);
			     pl--)
				swap(pl, pl-1);
		return;
	}
	pm = a + (n / 2);
	if (n > 7) {
		pl = a;
		pn = a + (n - 1);
		if (n > 40) {
			d = (n / 8);
			pl = med3(pl, pl + d, pl + 2 * d, dir);
			pm = med3(pm - d, pm, pm + d, dir);
			pn = med3(pn - 2 * d, pn - d, pn, dir);
		}
		pm = med3(pl, pm, pn, dir);
	}
	swap(a, pm);
	pa = pb = a + 1;

	pc = pd = a + (n - 1);
	for (;;) {
		while (pb <= pc && (r = cmp(pb, a, dir)) <= 0) {
			if (r == 0) {
				swap_cnt = 1;
				swap(pa, pb);
				pa++;
			}
			pb++;
		}
		while (pb <= pc && (r = cmp(pc, a, dir)) >= 0) {
			if (r == 0) {
				swap_cnt = 1;
				swap(pc, pd);
				pd--;
			}
			pc--;
		}
		if (pb > pc)
			break;
		swap(pb, pc);
		swap_cnt = 1;
		pb++;
		pc--;
	}
	if (swap_cnt == 0) {  /* Switch to insertion sort */
		for (pm = a + 1; pm < a+n; pm++)
			for (pl = pm;
			     (pl > a) && (cmp(pl-1, pl, dir) > 0);
			     pl--)
				swap(pl, pl-1);
		return;
	}

	pn = a + n;
	r = MIN(pa - a, pb - pa);
	vecswap(a, pb - r, r);
	r = MIN(pd - pc, pn - pd - 1);
	vecswap(pb, pn - r, r);
	if (((r = pb - pa) > 1) && ((unsigned)r >= left))
		qsort_buckets(a, r, left, right, dir);
	if (((r = pd - pc) > 1) && (n - r <= right)) {
		/* Iterate rather than recurse to save stack space */
		if (n - r > left)
			left = 0;
		else
			left -= n - r;
		right -= n - r;
		a += n - r;
		n = r;
		goto loop;
	}
/*		qsort(pn - r, r, cmp);*/
}

/* vim:set ts=3 sw=3 tw=78 expandtab: */
