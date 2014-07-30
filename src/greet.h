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

/* $Id: greet.h,v 1.21 2008/03/27 20:57:19 evertonm Exp $ */

#ifndef NEPIM_GREET_H
#define NEPIM_GREET_H

typedef struct nepim_greet_t nepim_greet_t;

struct nepim_greet_t {
  int            must_send;
  long long      bit_rate;
  int            pkt_rate;
  int            stat_interval;
  int            test_duration;
  long           write_delay;
  int            keepalive_must_send;
  int            keepalive_require;
  int            keepalive_timeout;
  int            keepalive_send_delay;
  unsigned       seed;
  unsigned       verify_data;
  int            random_fill;
  unsigned char  fill_byte;
  int            pause_duration;
  int            socket_keepalive;
  int            nagle;
  int            overhead;
  int            sweep_random;
  int            sweep_step;
  int            write_floor;
  int            write_ceil;
  int            report_partial_min_max;
  int            mss;
  char          *password_buf;
  int            password_buf_size;
};

int nepim_write_greetings(const nepim_greet_t *opt, char *buf,
                          int buf_size);

int nepim_parse_greetings(nepim_greet_t *opt, int is_tcp,
                          const char *buf, const char *past_end);

#endif /* NEPIM_GREET_H */

