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

/* $Id: tcpwrap.c,v 1.7 2006/06/05 10:20:54 evertonm Exp $ */

#include <stdio.h>
#include <assert.h>

#include "tcpwrap.h"

#define NEPIM_TCPWRAP_DENY   (0)
#define NEPIM_TCPWRAP_PERMIT (-1)

#ifdef HAVE_DLOPEN

#include <dlfcn.h>

#ifndef RTLD_LAZY
# define RTLD_LAZY 0x00001
#endif

typedef int (*nepim_hosts_ctl_t)(const char *daemon,
				 const char *client_name,
				 const char *client_addr,
				 const char *client_user);

static void              *libwrap        = 0;
static nepim_hosts_ctl_t local_hosts_ctl = 0;

#ifndef STRING_UNKNOWN /* <tcpd.h> */
# define STRING_UNKNOWN "unknown"
#endif

static nepim_hosts_ctl_t load_hosts_ctl(const char *lib_name)
{
  if (!local_hosts_ctl) {
    if (!libwrap) {
      libwrap = dlopen(lib_name, RTLD_LAZY);

      if (!libwrap)
	return 0;
    }

    local_hosts_ctl = (nepim_hosts_ctl_t)
      dlsym(libwrap, "hosts_ctl");
  }

  return local_hosts_ctl;
}

#endif /* HAVE_DLOPEN */

int nepim_hosts_ctl(const char *lib_name,
		    const char *daemon,
		    const char *client_addr)
{
#ifdef HAVE_DLOPEN
  if (!load_hosts_ctl(lib_name)) {
    char *err = dlerror();

    fprintf(stderr, 
	    "%s: %s: could not load TCP wrapper %s/hosts_ctl(): %s\n",
	    __FILE__, __PRETTY_FUNCTION__, lib_name, err ? err : "?");
    
    return NEPIM_TCPWRAP_DENY;
  }

  assert(local_hosts_ctl);

  return local_hosts_ctl(daemon, STRING_UNKNOWN,
			 client_addr, STRING_UNKNOWN);
#else 
  fprintf(stderr, 
	  "%s: %s: missing support for TCP wrapper\n",
	  __FILE__, __PRETTY_FUNCTION__);

  return NEPIM_TCPWRAP_DENY;
#endif /* HAVE_DLOPEN */
}
