#!/bin/sh

fail() {
	echo "$(basename $0): $1" >&2
	exit 1
}

dir="$1"
[ -d "$dir" ] || fail "no such dir $dir"

name=potatofs_rw_integrity
out=$(mktemp -t potatofs_rw_integrity_small_$(date +'%Y-%m-%d').out.XXXXXX)

if ! fio --name="$name" \
	--output="$out" \
	--directory "$dir" \
	--group_reporting=1 \
	--rw=randrw \
	--rwmixread=60 \
	--rwmixwrite=40 \
	--bs=4K \
	--direct=0 \
	--numjobs=4 \
	--time_based=1 \
	--runtime=300 \
	--size=200M \
	--nrfiles=100 \
	--openfiles=50 \
	--ioengine=psync \
	--iodepth=1 \
	--do_verify=1 \
	--verify_fatal=1 \
	--verify_state_save=0 \
	--verify=crc32c; then
	exit 1
fi

echo "Output: $out"
