#!/bin/sh

fatal() {
	echo "error: $1" >&2
	exit 1
}

basepath="$(mktemp -d -t potatofs.XXXXXX)"


[ -x ./potatofs ] || fatal "potatofs is not found or executable"
[ -x ./potatofs_tests ] || fatal "potatofs_tests is not found or executable"
[ -d "$basepath" ] || fatal "temp dir not found"

cp mgr.pl.sample "$basepath/mgr.pl"

mountpoint="$basepath/mnt"
datapath="$basepath/data"
conf="$basepath/conf"
cat > "$conf" << EOF
data_dir: $datapath
mgr_socket_path: $datapath/potatomgr.sock
backend: $basepath/mgr.pl
unclaim_purge_threshold_pct: 90
purge_threshold_pct: 0
EOF

mkdir "$mountpoint" "$datapath" || fatal "failed to create directories"

echo "*** Mounting $mountpoint; waiting for mount complete ***"
./potatomgr -c "$conf" -w 1 -W 1 -p "$basepath/potatomgr.pid"
./potatofs -o cfg_path="$conf" "$mountpoint" &
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
kill `cat $basepath/potatomgr.pid`
if [ $st -eq 0 ]; then
	rm -rf "$basepath"
	echo "Done."
else
	echo "Encountered errors; not cleaning data dir at $basepath"
fi

exit $?
