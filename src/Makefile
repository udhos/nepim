#
# $Id: Makefile,v 1.38 2014/07/10 06:39:56 evertonm Exp $
#

# If the following aren't defined, nepim
# defines some internal types as work-arounds.
# It's always safer to have them defined, if
# the environment supports them.
# 
#   HAVE_IP_MREQN
#   HAVE_IP_MREQ
#   HAVE_IPV6_MREQ
#   HAVE_SIGHANDLER_T
#   HAVE_SUSECONDS_T
#   HAVE_GROUP_SOURCE_REQ
# 
# The following are for portable definitions
# of uint8_t/uint16_t/uint32_t:
# 
#   HAVE_STDINT   -- for systems with <stdint.h>         
#   HAVE_INTTYPES -- for systems with <inttypes.h>
#
# The definition below specifies how to access
# the 4 32-bit address pieces under struct in6_addr:
#
#   HAVE_INET6_S6_ADDR32 -- s6_addr32[i]
#   HAVE_INET6_IN6_U     -- in6_u.u6_addr32[i]
#   HAVE_INET6_S6_UN     -- _S6_un._S6_u32[i]
#   HAVE_INET6_U6_ADDR   -- __u6_addr.__u6_addr32[i]
# 
# The following is specific for Solaris,
# which seems to demand a "uchar" argument
# for setsockopt(IP_MULTICAST_TTL):
# 
#   HAVE_UCHAR_MCAST_TTL
#
# Systems with dlopen(3) support should have
# ENABLE_DLOPEN defined as -DHAVE_DLOPEN.
# Otherwise, tcpwrapper support is disabled.

OOP_BASE = /usr/local/oop
OOP_INC  = $(OOP_BASE)/include
OOP_LIB  = $(OOP_BASE)/lib

ENABLE_DLOPEN = -DHAVE_DLOPEN

CC      = gcc
WARN    = -Wall
REENT   = -D_REENTRANT
#DEBUG   = -DNEPIM_DEBUG_KEEPALIVE -DNEPIM_DEBUG_FIXME
CFLAGS  = $(WARN) $(REENT) $(DEBUG) -g -ggdb -I$(OOP_INC) $(ENABLE_DLOPEN) \
	 -DHAVE_IPV6_MREQ
LDFLAGS += -L$(OOP_LIB) -loop

PLATFORM=$(shell uname)

ifeq ($(PLATFORM),SunOS)
SPARC64 = -m64 -mcpu=v9
CFLAGS += -DHAVE_SUSECONDS_T -DHAVE_UCHAR_MCAST_TTL -DHAVE_INTTYPES \
	-DHAVE_IP_MREQ -DHAVE_INET6_S6_UN $(SPARC64)
LDFLAGS += $(SPARC64) -R$(OOP_LIB)
LDFLAGS += -lsocket -lnsl
ifdef ENABLE_DLOPEN
LDFLAGS += -ldl
endif
endif

ifeq ($(PLATFORM),Linux)
CFLAGS += -DHAVE_STDINT -DHAVE_SUSECONDS_T \
	-DHAVE_SIGHANDLER_T -DHAVE_IP_MREQN -DHAVE_IP_MREQ \
	-DHAVE_INET6_S6_ADDR32 \
	-DHAVE_GROUP_SOURCE_REQ
ifdef ENABLE_DLOPEN
LDFLAGS += -ldl
endif
endif

ifeq ($(PLATFORM),NetBSD)
CFLAGS += -DHAVE_INTTYPES -DHAVE_UCHAR_MCAST_TTL -DHAVE_INET6_U6_ADDR
endif

ifeq ($(PLATFORM),OpenBSD)
CFLAGS += -DHAVE_INTTYPES -DHAVE_UCHAR_MCAST_TTL -DHAVE_INET6_U6_ADDR
endif

ifeq ($(PLATFORM),FreeBSD)
CFLAGS += -DHAVE_INTTYPES -DHAVE_INET6_U6_ADDR
endif

OBJ    = main.o conf.o sock.o session.o pipe.o \
	common.o client.o server.o slot.o \
	udp_server.o udp_client.o greet.o \
	array.o usock.o str.o udp_header.o int.o \
	tcpwrap.o rand.o version.o

TARGET = nepim

.PHONY: default
default: $(TARGET)

.PHONY: clean
clean:
	rm -f *.o *~ $(TARGET)

.PHONY: build
build: clean default

$(TARGET): $(OBJ)
	$(CC) -o $@ $^ $(LDFLAGS)
