#!/bin/sh

backend_path="/dev/shm/potatofs_backend"

usage() {
	echo "Usage: $(basename $0) -h <command>"
	echo ""
	echo "       $(basename $0) df"
	echo ""
	echo "           Output is <used bytes> / <total available bytes>"
	echo ""
	echo "       $(basename $0) get <slab name> <local path>"
	echo ""
	echo "           <slab name> is the file name, local path is the"
	echo "           absolute path of the slab file."
	echo ""
	echo "       $(basename $0) put <local name> <slab name>"
	echo ""
	echo "           <slab name> is the file name, local path is the"
	echo "           absolute path of the slab file."
}


if [ "$1" = "-h" ]; then
	usage
	exit 2
fi

do_df() {
	df_out=$(df -k $backend_path | tail -1)
	if [ $? -ne 0 ]; then
		echo '{"status": "ERR", "msg": "df failed"}'
		return 1
	fi

	total=$((`echo $df_out | cut -d' ' -f 2` * 1024))
	used=$((`echo $df_out | cut -d' ' -f 3` * 1024))
	echo "{\"status\": \"OK\", \"used_bytes\": $used, \"total_bytes\": $total}"
}

do_get() {
	slab=$1
	local_path=$2
	if [ ! -r "$backend_path/$slab" ]; then
		echo "{\"status\": \"ERR_NOENT\", \"msg\": \"no such slab on backend: $slab\"}"
		return 1
	fi
	sz=$(stat -c %s "$backend_path/$slab")
	cp "$backend_path/$slab" "$local_path"
	if [ $? -ne 0 ]; then
		echo "{\"status\": \"ERR\", \"msg\": \"failed to get slab: $slab\"}"
		return 1
	fi
	echo "{\"status\": \"OK\", \"in_bytes\": $sz}"
}

do_put() {
	local_path=$1
	slab=$2
	if [ ! -r "$local_path" ]; then
		echo "{\"status\": \"ERR\", \"msg\": \"no such slab: $local_path\"}"
		return 1
	fi
	sz=$(stat -c %s "$local_path")
	cp "$local_path" "$backend_path/$slab"
	if [ $? -ne 0 ]; then
		echo "{\"status\": \"ERR\", \"msg\": \"failed to put slab: $slab\"}"
		return 1
	fi
	echo "{\"status\": \"OK\", \"out_bytes\": $sz}"
}

mkdir -p $backend_path

case $1 in
	df)
		do_df
		;;
	get)
		do_get $2 $3
		;;
	put)
		do_put $2 $3
		;;
	*)
		usage
		exit 2
esac

exit $?
