#!/bin/sh

fatal() {
	echo "error: $1" >&2
	exit 1
}

warn() {
	echo "error: $1" >&2
}

ulimit -c unlimited

export BACKEND_DATA_PATH="$(mktemp -d /dev/shm/potatofs_backend.XXXXXX)"
basepath="$(mktemp -d /dev/shm/potatofs.XXXXXX)"

[ -x ./potatofs ] || fatal "potatofs is not found or executable"
[ -x ./potatofs_tests ] || fatal "potatofs_tests is not found or executable"
[ -d "$basepath" ] || fatal "temp dir not found"
[ -d "$BACKEND_DATA_PATH" ] || fatal "backend temp dir not found"

cp backends/backend_cp.sh "$basepath/backend"

mountpoint="$basepath/mnt"
datapath="$basepath/data"
conf="$basepath/conf"

# We don't want the purger to kick in here since we need to
# inspect the on-disk slabs after our tests. We also disable the
# purger process in the potatomgr invocation.
cat > "$conf" << EOF
data_dir: $datapath
mgr_socket_path: $basepath/potatomgr.sock
pidfile_path: $basepath/potatomgr.pid
backend: $basepath/backend
# The purge thread runs every 10 seconds so we can expect them to be
# unloaded after this much time. Keep this value low to have tests run
# in a short time.
slab_max_age: 1
unclaim_purge_threshold_pct: 100
purge_threshold_pct: 100
noatime: no
EOF

mkdir "$mountpoint" "$datapath" || fatal "failed to create directories"

echo "*** Mounting $mountpoint; waiting for mount complete ***"
./potatomgr -c "$conf" -w 1 -W 1 -S 0 -P 0
./potatofs -f -o cfg_path="$conf" "$mountpoint" &
for i in 1 2 3 4 5; do
	if [ "$(stat -c '%i' "$mountpoint")" = "1" ]; then
		break
	fi
	[ $i -eq 5 ] && fatal "timeout while mounting"
	sleep 1
done
mgr_pid=`cat $basepath/potatomgr.pid`
echo ""

echo "*** Running tests ***"
./potatofs_tests -c "$conf" "$mountpoint"
st=$?
echo ""

echo "*** Unmounting ***"
fusermount -u "$mountpoint"
wait
while kill -0 $mgr_pid 2>/dev/null; do sleep 1; done
echo ""

echo "*** fsck ***"
./potatomgr -c "$conf" -w 1 -W 1 -T 3600
./potatoctl -c "$conf" fsck quiet || warn "fsck had errors"
./potatoctl -c "$conf" shutdown
echo ""

echo "*** cleanup ***"
while $binpath/potatoctl -c $conf status >/dev/null 2>&1; do
	sleep 1
done
if [ $st -eq 0 ]; then
	rm -rf "$basepath"
	rm -rf "$BACKEND_DATA_PATH"
	echo "Done."
else
	echo "Encountered errors; not cleaning data dir at $basepath"
fi

exit $?
