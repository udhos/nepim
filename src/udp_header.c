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

/* $Id: udp_header.c,v 1.13 2006/05/11 14:03:17 evertonm Exp $ */

#include <sys/types.h>
#include <netinet/in.h>
#include <stdio.h>
#include <assert.h>

#include "udp_header.h"

/* 
   version     1
   local_slot  2
   remote_slot 2
   type        1
   seq         8
   seed        4
*/
const int UDP_HEADER_LEN = 1 + 2 + 2 + 1 + 8 + 4; /* 18 */

static const int UDP_HDR_OFF_VERSION  = 0;
static const int UDP_HDR_OFF_DST_SLOT = 1;
static const int UDP_HDR_OFF_SRC_SLOT = 3;
static const int UDP_HDR_OFF_TYPE     = 5;
static const int UDP_HDR_OFF_SEQ      = 6;
static const int UDP_HDR_OFF_SEED     = 14;

int nepim_udp_hdr_parse(nepim_udp_hdr_t *hdr, const char *buf, int buf_size)
{
  if (buf_size < UDP_HEADER_LEN)
    return -1;
  
  hdr->version  = buf[UDP_HDR_OFF_VERSION];
  hdr->dst_slot = nepim_uint16_read(buf + UDP_HDR_OFF_DST_SLOT);
  hdr->src_slot = nepim_uint16_read(buf + UDP_HDR_OFF_SRC_SLOT);
  hdr->type     = buf[UDP_HDR_OFF_TYPE];
  hdr->seq      = nepim_uint64_read(buf + UDP_HDR_OFF_SEQ);
  hdr->seed     = nepim_uint32_read(buf + UDP_HDR_OFF_SEED);

#if 0
  fprintf(stderr,
	  "ERASEME DEBUG parse SEQ = %llu (type=%d)\n",
	  hdr->seq, hdr->type);
#endif
  
  return 0;
}

void nepim_udp_hdr_write(const nepim_udp_hdr_t *hdr, char *buf, int buf_size)
{
  assert(buf_size >= UDP_HEADER_LEN);

#if 0
  fprintf(stderr,
	  "ERASEME DEBUG write SEQ = %llu\n",
	  hdr->seq);
#endif
  
  buf[UDP_HDR_OFF_VERSION] = hdr->version;
  nepim_uint16_write(buf + UDP_HDR_OFF_DST_SLOT, hdr->dst_slot);
  nepim_uint16_write(buf + UDP_HDR_OFF_SRC_SLOT, hdr->src_slot);
  buf[UDP_HDR_OFF_TYPE] = hdr->type;
  nepim_uint64_write(buf + UDP_HDR_OFF_SEQ, hdr->seq);
  nepim_uint32_write(buf + UDP_HDR_OFF_SEED, hdr->seed);
}
