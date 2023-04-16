DEPDIR := .deps
CC := gcc
CFLAGS := -Wall -g -DFUSE_USE_VERSION=26 \
	$(shell pkg-config --cflags fuse uuid libbsd-overlay) \
	-fstack-protector-strong
LDFLAGS := $(shell pkg-config --libs fuse uuid 'jansson >= 2.9' \
	libbsd-overlay libbsd-ctor sqlite3 zlib) \
	-Wl,-z,relro -Wl,-z,now
EXTRA_CFLAGS :=

DEPFLAGS = -MMD -MP -MF $(DEPDIR)/$@.d

SRCS = slabs.c inodes.c dirinodes.c openfiles.c xlog.c util.c \
	fs_error.c fs_info.c potatofs.c counters.c mgr.c config.c \
	potatomgr.c slabdb.c
OBJS = $(SRCS:.c=.o)

CTLSRCS = potatoctl.c slabs.c inodes.c dirinodes.c openfiles.c xlog.c util.c \
	fs_error.c fs_info.c counters.c mgr.c config.c slabdb.c potatomgr.c
CTLOBJS = $(CTLSRCS:.c=.o)

TESTSRCS = potatofs_tests.c slabs.c inodes.c dirinodes.c openfiles.c xlog.c \
	util.c fs_error.c fs_info.c counters.c mgr.c config.c slabdb.c
TESTOBJS = $(TESTSRCS:.c=.o)

all: potatofs potatoctl potatofs_tests

potatofs: $(OBJS)
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) -o potatofs $(OBJS) $(LDFLAGS)

potatoctl: $(CTLOBJS)
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) -o potatoctl $(CTLOBJS) $(LDFLAGS) \
		`pkg-config --cflags --libs ncurses`

potatofs_tests: $(TESTOBJS)
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) -o potatofs_tests \
		$(TESTOBJS) $(LDFLAGS)

tests: potatofs_tests
	./potatofs_tests.sh

.c.o:
	@mkdir -p $(DEPDIR)
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) $(DEPFLAGS) -c $<

.PHONY: clean

clean:
	rm -f *.o potatofs potatoctl potatofs_tests $(DEPDIR)/* *.gcda *.gcno *.gcov
	test -d $(DEPDIR) && rmdir $(DEPDIR) || true

-include $(DEPDIR)/*
