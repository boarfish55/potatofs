#!/bin/sh

target="$1"
nops="$2"
if [ ! -d "$target" ]; then
	echo "$(basename $0): target dir does not exist"
	exit 1
fi

if [ -z "$nops" ]; then
	nops=100
fi

# Set rename=0 when running helgrind to silence errors about lock order.
# Lock ordering depends on directory parent/child relationships. If we
# move a child out of a parent, then move that parent back into the child,
# helgrind thinks this is a potential deadlock.
fsstress -d "$target" -s 111 -p 4 -n "$nops" -v -z \
	-f afsync=1 \
	-f aread=1 \
	-f awrite=1 \
	-f bulkstat=1 \
	-f bulkstat1=1 \
	-f chown=1 \
	-f copyrange=1 \
	-f creat=1 \
	-f fdatasync=1 \
	-f fsync=1 \
	-f getattr=1 \
	-f getdents=1 \
	-f link=1 \
	-f mkdir=1 \
	-f mknod=1 \
	-f mread=1 \
	-f mwrite=1 \
	-f zero=1 \
	-f insert=1 \
	-f read=1 \
	-f readlink=1 \
	-f readv=1 \
	-f rename=1 \
	-f rnoreplace=1 \
	-f rexchange=1 \
	-f rwhiteout=1 \
	-f rmdir=1 \
	-f sync=1 \
	-f truncate=1 \
	-f unlink=1 \
	-f write=1 \
	-f writev=1 | tee /tmp/fsstress.out
