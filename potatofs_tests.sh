#!/bin/sh

fatal() {
	echo "error: $1" >&2
	exit 1
}

basepath="$(mktemp -d -t potatofs.XXXXXX)"

[ -x ./potatofs ] || fatal "potatofs is not found or executable"
[ -x ./potatofs_tests ] || fatal "potatofs_tests is not found or executable"
[ -d "$basepath" ] || fatal "temp dir not found"

mountpoint="$basepath/mnt"
datapath="$basepath/data"

mkdir "$mountpoint" "$datapath" || fatal "failed to create directories"

echo "*** Mounting $mountpoint; waiting for mount complete ***"
./potatofs -o data_path="$datapath",slab_max_age=5 "$mountpoint" &
for i in 1 2 3 4 5; do
	if [ "$(stat -c '%i' "$mountpoint")" = "1" ]; then
		break
	fi
	[ $i -eq 5 ] && fatal "timeout while mounting"
	sleep 1
done
echo ""

echo "*** Running tests ***"
./potatofs_tests "$datapath" "$mountpoint"
st=$?
echo ""

echo "*** Unmounting ***"
fusermount -u "$mountpoint"
wait
echo ""

echo "*** fsck ***"
./potatoctl "$datapath" fsck
echo ""

echo "*** cleanup ***"
if [ $st -eq 0 ]; then
	rm -rf "$basepath"
	echo "Done."
else
	echo "Encountered errors; not cleaning data dir at $basepath"
fi

exit $?
