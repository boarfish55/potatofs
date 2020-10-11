PROGNAME=PotatoFS
VERSION=0.1
DEPDIR := .deps
CFLAGS := -DPROGNAME=\"$(PROGNAME)\" -DVERSION=\"$(VERSION)\" \
	-DFUSE_USE_VERSION=26 $(shell pkg-config --cflags fuse uuid)
LDFLAGS := $(shell pkg-config --libs fuse uuid)
CC := gcc -Wall -Werror -g $(CFLAGS)

DEPFLAGS = -MMD -MP -MF $(DEPDIR)/$@.d

SRCS = slabs.c inodes.c dirinodes.c openfiles.c exlog.c util.c \
	fs_info.c potatofs.c counters.c
OBJS = $(SRCS:.c=.o)

CTLSRCS = potatoctl.c slabs.c inodes.c dirinodes.c openfiles.c exlog.c util.c \
	fs_info.c counters.c
CTLOBJS = $(CTLSRCS:.c=.o)

TESTSRCS = potatofs_tests.c slabs.c inodes.c dirinodes.c openfiles.c exlog.c \
	util.c fs_info.c counters.c
TESTOBJS = $(TESTSRCS:.c=.o)

all: potatofs potatoctl potatofs_tests

potatofs: $(OBJS)
	$(CC) -o potatofs $(OBJS) $(LDFLAGS)

potatoctl: $(CTLOBJS)
	$(CC) -o potatoctl $(CTLOBJS) \
		$(shell pkg-config --libs fuse uuid 'jansson >= 2.9')

potatofs_tests: $(TESTOBJS)
	$(CC) -o potatofs_tests $(TESTOBJS) \
		$(shell pkg-config --libs fuse uuid 'jansson >= 2.9')

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
