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

cp backends/test_backend.sh "$basepath/backend"

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
backend_config: $basepath/backend.conf
# The purge thread runs every 10 seconds so we can expect them to be
# unloaded after this much time. Keep this value low to have tests run
# in a short time.
slab_max_age: 1
unclaim_purge_threshold_pct: 100
purge_threshold_pct: 100
noatime: no
workers: 1
bgworkers: 1
scrubber_interval: 0
purger_interval: 0
backend_get_timeout: 5
backend_put_timeout: 5
backend_df_timeout: 5
shutdown_grace_period: 0
EOF

mkdir "$mountpoint" "$datapath" || fatal "failed to create directories"

# Make sure we have enough fds to complete our tests
ulimit -S -n 128000

echo "*** Multi-thread tests ***"
echo "*** Mounting $mountpoint; waiting for mount complete ***"
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
./potatofs_tests -c "$conf" "$mountpoint" "$@"
st=$?
echo ""

echo "*** Unmounting ***"
fusermount -u "$mountpoint"
wait
./potatoctl -c $conf wait
echo ""

echo "*** fsck ***"
./potatoctl -c "$conf" fsck
if [ $? -ne 0 ]; then
	st=$?
fi
./potatoctl -c $conf wait
echo ""


echo "*** Single-thread tests ***"
echo "*** Mounting $mountpoint; waiting for mount complete ***"
# Set a limit on virtual memory to test ENOMEM errors
old_v_ulimit="$(ulimit -S -v)"
ulimit -S -v 100000

./potatofs -s -f -o cfg_path="$conf" "$mountpoint" &
for i in 1 2 3 4 5; do
	if [ "$(stat -c '%i' "$mountpoint")" = "1" ]; then
		break
	fi
	[ $i -eq 5 ] && fatal "timeout while mounting"
	sleep 1
done
echo ""

ulimit -S -v $old_v_ulimit

echo "*** Running tests ***"
./potatofs_tests -c "$conf" "$mountpoint" ENOMEM
st=$?
echo ""

echo "*** Unmounting ***"
fusermount -u "$mountpoint"
wait
./potatoctl -c $conf wait
echo ""

echo "*** fsck ***"
./potatoctl -c "$conf" fsck
if [ $? -ne 0 ]; then
	st=$?
fi
./potatoctl -c $conf wait
echo ""

read -p "Press any key to cleanup..." PAUSE

echo "*** cleanup ***"
if [ $st -eq 0 ]; then
	rm -rf "$basepath"
	rm -rf "$BACKEND_DATA_PATH"
	echo "Done."
else
	echo "Encountered errors; not cleaning data dir at $basepath"
fi

exit $?
