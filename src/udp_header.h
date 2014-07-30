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

/* $Id: udp_header.h,v 1.7 2006/04/25 18:15:41 evertonm Exp $ */


#ifndef NEPIM_UDP_HEADER
#define NEPIM_UDP_HEADER

#include "int.h"

enum { 
  UDP_TYPE_DATA = 0,  /* normal payload for test flows */
  UDP_TYPE_HELLO,     /* initial greeting from client to server */
  UDP_TYPE_KEEPALIVE  /* keepalive packets from non-senders */
};

typedef struct nepim_udp_hdr_t nepim_udp_hdr_t;

struct nepim_udp_hdr_t {
  uint8_t  version;
  uint16_t dst_slot;
  uint16_t src_slot;
  uint8_t  type;
  uint64_t seq;
  uint32_t seed;
};

extern const int UDP_HEADER_LEN;

#define UDP_VERSION (0x01)

int nepim_udp_hdr_parse(nepim_udp_hdr_t *hdr, const char *buf, int buf_size);

void nepim_udp_hdr_write(const nepim_udp_hdr_t *hdr, char *buf, int buf_size);

#endif /* NEPIM_UDP_HEADER */
