#  ======================================================================
#      crashdmesg - VMCore Kernel Ring Buffer Dumper
#      [ Makefile ]
#      Copyright(c) 2011 by Hiroshi KIHIRA.
#  ======================================================================


# --------------------------------------------------
#   Compiler and Compiler flags
CC = gcc
CFLAGS = -Wall -Werror -std=c99 
CFLAGS += -static -O2 -mtune=amdfam10
RM = rm


# --------------------------------------------------
#   Variables
BIN  = crashdmesg
HEAD = crashdmesg_common.h
OBJS = obj/crashdmesg_fileutils.o \
       obj/crashdmesg_elfutils.o \
       obj/crashdmesg_main.o


# --------------------------------------------------
#   Default Targets
all: crashdmesg

debug:
	make CFLAGS="-Wall -std=c99 -static -O0 -mtune=amdfam10 -g" all
	@echo -e "\n    Warning! Compiled with Optimize Lv.0 and Debug.\n"


# --------------------------------------------------
#   crashdmesg
crashdmesg: $(OBJS)
	$(CC) $(CFLAGS) -o $(BIN) $(OBJS)

obj/crashdmesg_fileutils.o: crashdmesg_fileutils.c $(HEAD) 
	$(CC) $(CFLAGS) -o $@ -c $(addsuffix .c, $(basename $(notdir $@)))

obj/crashdmesg_elfutils.o:  crashdmesg_elfutils.c $(HEAD)
	$(CC) $(CFLAGS) -o $@ -c $(addsuffix .c, $(basename $(notdir $@)))

obj/crashdmesg_main.o:      crashdmesg_main.c $(HEAD)
	$(CC) $(CFLAGS) -o $@ -c $(addsuffix .c, $(basename $(notdir $@)))


# --------------------------------------------------
#   clean
.PHONY: clean
clean: 
	$(RM) -v $(OBJS)

.PHONY: distclean
distclean: 
	$(RM) -v $(OBJS)
	$(RM) -v $(BIN)


# ======================================================================