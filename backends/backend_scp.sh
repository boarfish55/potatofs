#!/bin/sh
#
# Copyright (C) 2020-2022 Pascal Lalonde <plalonde@overnet.ca>
#
# This file is part of PotatoFS, a FUSE filesystem implementation.
#
# PotatoFS is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

ssh_host="potatofs@<some host>"
backend_path="/var/potatofs_backend"

usage() {
	echo "Usage: $(basename $0) -h <command>"
	echo ""
	echo "       $(basename $0) df"
	echo ""
	echo "           Output is <used bytes> / <total available bytes>"
	echo ""
	echo "       $(basename $0) get <slab name> <local path> <inode> <base>"
	echo ""
	echo "           <slab name> is the file name, local path is the"
	echo "           absolute path of the slab file. <inode> and <base> "
	echo "           are provided for informational purposes."
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
	df_out=$(ssh -o ConnectTimeout=5 $ssh_host df -k $backend_path | \
		tail -1)
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
	inode=$3
	base=$4
	if [ -z "$slab" -o -z "$local_path" ]; then
		echo "{\"status\": \"ERR\", \"msg\": \"bad invocation\"}"
		return 2
	fi
	if ! ssh -o ConnectTimeout=5 $ssh_host \
		test -r "$backend_path/$slab"; then
		echo "{\"status\": \"ERR_NOENT\", \"msg\": \"no such slab on backend: $slab\"}"
		return 1
	fi
	scp -o ConnectTimeout=5 $ssh_host:$backend_path/$slab "$local_path"
	if [ $? -ne 0 ]; then
		echo "{\"status\": \"ERR\", \"msg\": \"failed to get slab: $slab\"}"
		return 1
	fi
	sz=$(stat -c %s "$local_path")
	echo "{\"status\": \"OK\", \"in_bytes\": $sz}"
	if [ ! -z "$inode" -a ! -z "$base" ]; then
		logger -i -t potatofs-backend -p user.info \
			"getting inode $inode / base $base"
	fi
}

do_put() {
	local_path=$1
	slab=$2
	if [ -z "$slab" -o -z "$local_path" ]; then
		echo "{\"status\": \"ERR\", \"msg\": \"bad invocation\"}"
		return 2
	fi
	if [ ! -r "$local_path" ]; then
		echo "{\"status\": \"ERR\", \"msg\": \"no such slab: $local_path\"}"
		return 1
	fi
	sz=$(stat -c %s "$local_path")
	scp -o ConnectTimeout=20 "$local_path" $ssh_host:$backend_path/$slab
	if [ $? -ne 0 ]; then
		echo "{\"status\": \"ERR\", \"msg\": \"failed to put slab: $slab\"}"
		return 1
	fi
	echo "{\"status\": \"OK\", \"out_bytes\": $sz}"
}

case $1 in
	df)
		do_df
		;;
	get)
		do_get $2 $3 $4 $5
		;;
	put)
		do_put $2 $3
		;;
	*)
		usage
		exit 2
esac

exit $?
