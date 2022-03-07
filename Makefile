DEPDIR := .deps
CFLAGS := -DFUSE_USE_VERSION=26 \
	$(shell pkg-config --cflags fuse uuid libbsd-overlay)
LDFLAGS := $(shell pkg-config --libs fuse uuid 'jansson >= 2.9' \
	libbsd-overlay sqlite3 zlib)
CC := gcc -Wall -Werror -g $(CFLAGS)

DEPFLAGS = -MMD -MP -MF $(DEPDIR)/$@.d

SRCS = slabs.c inodes.c dirinodes.c openfiles.c exlog.c util.c \
	fs_error.c fs_info.c potatofs.c counters.c mgr.c config.c
OBJS = $(SRCS:.c=.o)

MGRSRCS = potatomgr.c slabs.c exlog.c util.c fs_info.c counters.c mgr.c \
	fs_error.c config.c slabdb.c
MGROBJS = $(MGRSRCS:.c=.o)

CTLSRCS = potatoctl.c slabs.c inodes.c dirinodes.c openfiles.c exlog.c util.c \
	fs_error.c fs_info.c counters.c mgr.c config.c slabdb.c
CTLOBJS = $(CTLSRCS:.c=.o)

TESTSRCS = potatofs_tests.c slabs.c inodes.c dirinodes.c openfiles.c exlog.c \
	util.c fs_error.c fs_info.c counters.c mgr.c config.c
TESTOBJS = $(TESTSRCS:.c=.o)

all: potatofs potatoctl potatofs_tests potatomgr

potatofs: $(OBJS)
	$(CC) -o potatofs $(OBJS) $(LDFLAGS)

potatomgr: $(MGROBJS)
	$(CC) -o potatomgr $(MGROBJS) $(LDFLAGS)

potatoctl: $(CTLOBJS)
	$(CC) -o potatoctl $(CTLOBJS) $(LDFLAGS)

potatofs_tests: $(TESTOBJS)
	$(CC) -o potatofs_tests $(TESTOBJS) $(LDFLAGS)

tests: potatofs_tests
	./potatofs_tests.sh

.c.o:
	@mkdir -p $(DEPDIR)
	$(CC) $(DEPFLAGS) -c $<

.PHONY: clean

clean:
	rm -f *.o potatofs potatomgr potatoctl potatofs_tests $(DEPDIR)/*
	test -d $(DEPDIR) && rmdir $(DEPDIR) || true

-include $(DEPDIR)/*
