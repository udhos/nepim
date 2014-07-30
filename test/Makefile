#
# $Id: Makefile,v 1.3 2006/05/18 22:17:26 evertonm Exp $
#

NEPIM_SRC = ../src
NEPIM_OBJ = ../old

CC      = gcc
CFLAGS  = -Wall -g -ggdb -I$(NEPIM_SRC) -I$(NEPIM_OBJ)

WINOBJ  = test-win.o $(NEPIM_OBJ)/win.o $(NEPIM_OBJ)/bit.o

TARGET = test-win test-oop-timer

.PHONY: default
default: $(TARGET)

.PHONY: clean
clean:
	rm -f *.o *~ $(TARGET)

.PHONY: build
build: clean default

$(NEPIM_OBJ)/win.o:
	$(MAKE) -C $(NEPIM_SRC)

$(NEPIM_OBJ)/bit.o:
	$(MAKE) -C $(NEPIM_SRC)

test-win: $(WINOBJ)
	$(CC) $(LDFLAGS) -o $@ $^

test-oop-timer: test-oop-timer.o
	$(CC) $(LDFLAGS) -loop -o $@ $^
