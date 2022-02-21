#!/bin/sh

fatal() {
	echo "error: $1" >&2
	exit 1
}

backend_data_path=/dev/shm/potatofs_backend
basepath="$(mktemp -d /dev/shm/potatofs.XXXXXX)"

[ -x ./potatofs ] || fatal "potatofs is not found or executable"
[ -x ./potatofs_tests ] || fatal "potatofs_tests is not found or executable"
[ -d "$basepath" ] || fatal "temp dir not found"

cp backends/backend_cp.sh "$basepath/backend"

mountpoint="$basepath/mnt"
datapath="$basepath/data"
conf="$basepath/conf"

# We don't want the purger to kick in here since we need to
# inspect the on-disk slabs after our tests. We also disable the
# purger process in the potatomgr invocation.
cat > "$conf" << EOF
data_dir: $datapath
mgr_socket_path: $datapath/potatomgr.sock
backend: $basepath/backend
slab_max_age: 60
unclaim_purge_threshold_pct: 100
purge_threshold_pct: 100
noatime: no
EOF

mkdir "$mountpoint" "$datapath" || fatal "failed to create directories"

echo "*** Mounting $mountpoint; waiting for mount complete ***"
./potatomgr -c "$conf" -w 1 -W 1 -S 0 -P 0 -p "$basepath/potatomgr.pid"
./potatofs -f -o cfg_path="$conf" "$mountpoint" &
for i in 1 2 3 4 5; do
	if [ "$(stat -c '%i' "$mountpoint")" = "1" ]; then
		break
	fi
	[ $i -eq 5 ] && fatal "timeout while mounting"
	sleep 1
done
echo ""

echo "*** Running tests ***"
./potatofs_tests -c "$conf" "$mountpoint"
st=$?
echo ""

echo "*** Unmounting ***"
fusermount -u "$mountpoint"
wait
echo ""

echo "*** fsck ***"
./potatoctl -c "$conf" fsck
echo ""

echo "*** cleanup ***"
pid=`cat $basepath/potatomgr.pid`
kill $pid
while kill -0 $pid 2>/dev/null; do sleep 1; done
if [ $st -eq 0 ]; then
	rm -rf "$basepath"
	rm -rf "$backend_data_path"
	echo "Done."
else
	echo "Encountered errors; not cleaning data dir at $basepath"
fi

exit $?
