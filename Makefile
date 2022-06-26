DEPDIR := .deps
CFLAGS := -DFUSE_USE_VERSION=26 \
	$(shell pkg-config --cflags fuse uuid libbsd-overlay)
LDFLAGS := $(shell pkg-config --libs fuse uuid 'jansson >= 2.9' \
	libbsd-overlay libbsd-ctor sqlite3 zlib)
CC := gcc -Wall -Werror -g $(CFLAGS)

DEPFLAGS = -MMD -MP -MF $(DEPDIR)/$@.d

SRCS = slabs.c inodes.c dirinodes.c openfiles.c xlog.c util.c \
	fs_error.c fs_info.c potatofs.c counters.c mgr.c config.c \
	potatomgr.c slabdb.c
OBJS = $(SRCS:.c=.o)

FAKEFS_SRCS = dirinodes.c xlog.c fake_fs.c
FAKEFS_OBJS = $(FAKEFS_SRCS:.c=.o)

CTLSRCS = potatoctl.c slabs.c inodes.c dirinodes.c openfiles.c xlog.c util.c \
	fs_error.c fs_info.c counters.c mgr.c config.c slabdb.c potatomgr.c
CTLOBJS = $(CTLSRCS:.c=.o)

TESTSRCS = potatofs_tests.c slabs.c inodes.c dirinodes.c openfiles.c xlog.c \
	util.c fs_error.c fs_info.c counters.c mgr.c config.c slabdb.c
TESTOBJS = $(TESTSRCS:.c=.o)

all: potatofs potatoctl potatofs_tests fake_fs

potatofs: $(OBJS)
	$(CC) -o potatofs $(OBJS) $(LDFLAGS)

fake_fs: $(FAKEFS_OBJS)
	$(CC) -o fake_fs $(FAKEFS_OBJS) $(LDFLAGS)

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
	rm -f *.o potatofs potatoctl potatofs_tests $(DEPDIR)/*
	test -d $(DEPDIR) && rmdir $(DEPDIR) || true

-include $(DEPDIR)/*
