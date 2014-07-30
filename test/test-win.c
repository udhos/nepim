/*-GNU-GPL-BEGIN-*
nepim - network pipemeter - measuring network bandwidth between hosts
Copyright (C) 2005  Everton da Silva Marques

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or (at
your option) any later version.

This program is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; see the file COPYING; if not, write to the
Free Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston,
MA 02110-1301 USA
*-GNU-GPL-END-*/

/* $Id: test-win.c,v 1.8 2005/11/04 09:56:15 evertonm Exp $ */

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

#include "win.h"

const char * prog_name;

static void go(nepim_win_t *win_recv_seq)
{
  int total_lost = 0;
  int total_dup = 0;
  int recv = 0;
  int lost;
  int dup;
  int pending_loss;
  int seq;

  fprintf(stderr, "%s: reading from input\n", prog_name);

  for (;;) {
    char buf[1000];
    int i;

    if (!fgets(buf, sizeof(buf), stdin)) {
      if (!feof(stdin))
	fprintf(stderr, 
		"%s: unexpected input error: errno=%d %s\n",
		prog_name, errno, strerror(errno));

      break;
    }

    seq = atoi(buf);
    ++recv;

    lost = 0;
    dup  = 0;

    nepim_win_add(win_recv_seq, seq, &lost, &dup);

    total_lost += lost;
    total_dup  += dup;

    fprintf(stdout, "%4d ", seq);

    for (i = 0; i < win_recv_seq->max_size; ++i)
      fprintf(stdout, "%s",
	      nepim_bit_isset(&win_recv_seq->bit_set, i) ? "1" : "0");

    fprintf(stdout, " recv=%3d lost=%3d/%3d dup=%3d/%3d E=%3u\n",
	    recv, lost, total_lost, dup, total_dup,
	    win_recv_seq->seq_expect);
  }

  fprintf(stderr, "%s: input done\n", prog_name);

  pending_loss = nepim_win_extract_loss(win_recv_seq);

  fprintf(stdout, "pending_loss=%d\n", pending_loss);

  total_lost += pending_loss;

  fprintf(stdout, 
	  "total: recv=%d loss=%d dup=%d\n",
	  recv, total_lost, total_dup);
}

int main(int argc, const char *argv[])
{
  nepim_win_t win_recv_seq;
  int win_max = 40;

  prog_name = argv[0];

  if (argc > 1)
    win_max = atoi(argv[1]);

  fprintf(stdout, "%s: win_max=%d\n", prog_name, win_max);

  nepim_win_init(&win_recv_seq, win_max);

  go(&win_recv_seq);

  nepim_win_del(&win_recv_seq);

  exit(0);
}
