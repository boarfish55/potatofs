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

# This backend is used to simulate a slow remote backend. It just copies
# to a local directory and introduces some sleep.

if [ ! -d "$BACKEND_DATA_PATH" ]; then
	BACKEND_DATA_PATH="/dev/shm/potatofs_backend"
fi

usage() {
	echo "Usage: $(basename $0) -h <command>"
	echo ""
	echo "       $(basename $0) df"
	echo ""
	echo "           Output is a JSON string with the following format:"
	echo ""
	echo "           {\"status\": \"OK\", "
	echo "            \"used_bytes\": <bytes used on backend>, "
	echo "            \"total_bytes\": <total backend capacity in bytes>}"
	echo ""
	echo "       $(basename $0) <get|put>"
	echo ""
	echo "           This will read a JSON string from STDIN. It should "
	echo "           follow this form:"
	echo ""
	echo "           {\"backend_name\": \"<slab name>\","
	echo "            \"local_path\": \"<local slab path>\","
	echo "            \"inode\": <inode number>,"
	echo "            \"base\": <slab base>}"
	echo ""
	echo "           The commands get and put a slab from / to the "
	echo "           backend respectively."
	echo "           <backend_name> is the file name to be used on the backend,"
	echo "           <local_path> is the absolute path of the slab file on the cache "
	echo "           partition. <inode> and <base> are provided for informational "
	echo "           purposes."
}

if [ "$1" = "-h" ]; then
	usage
	exit 2
fi

do_df() {
	df_out=$(df -k $BACKEND_DATA_PATH | tail -1)
	if [ $? -ne 0 ]; then
		echo '{"status": "ERR", "msg": "df failed"}'
		return 1
	fi

	total=$((`echo $df_out | cut -d' ' -f 2` * 1024))
	used=$((`echo $df_out | cut -d' ' -f 3` * 1024))
	echo "{\"status\": \"OK\", \"used_bytes\": $used, \"total_bytes\": $total}"
}

do_get() {
	read json
	slab=$(echo $json | jq -r .backend_name)
	local_path=$(echo $json | jq -r .local_path)
	inode=$(echo $json | jq -r .inode)
	base=$(echo $json | jq -r .base)

	if [ -z "$slab" -o -z "$local_path" ]; then
		echo "{\"status\": \"ERR\", \"msg\": \"bad invocation\"}"
		return 2
	fi
	if [ ! -r "$BACKEND_DATA_PATH/$slab" ]; then
		echo "{\"status\": \"ERR_NOSLAB\", \"msg\": \"no such slab on backend: $slab\"}"
		return 1
	fi
	sz=$(stat -c %s "$BACKEND_DATA_PATH/$slab")
	if [ -r "$BACKEND_DATA_PATH/sleep" ]; then
		sleep `cat $BACKEND_DATA_PATH/sleep`
	fi
	cp "$BACKEND_DATA_PATH/$slab" "$local_path"
	if [ $? -ne 0 ]; then
		echo "{\"status\": \"ERR\", \"msg\": \"failed to get slab: $slab\"}"
		return 1
	fi
	echo "{\"status\": \"OK\", \"in_bytes\": $sz}"
	if [ ! -z "$inode" -a ! -z "$base" ]; then
		logger -i -t potatofs-backend -p user.info \
			"getting inode $inode / base $base"
	fi
}

do_put() {
	read json
	slab=$(echo $json | jq -r .backend_name)
	local_path=$(echo $json | jq -r .local_path)
	inode=$(echo $json | jq -r .inode)
	base=$(echo $json | jq -r .base)

	if [ -z "$slab" -o -z "$local_path" ]; then
		echo "{\"status\": \"ERR\", \"msg\": \"bad invocation\"}"
		return 2
	fi
	if [ ! -r "$local_path" ]; then
		echo "{\"status\": \"ERR\", \"msg\": \"no such slab: $local_path\"}"
		return 1
	fi
	sz=$(stat -c %s "$local_path")
	cp "$local_path" "$BACKEND_DATA_PATH/$slab"
	if [ $? -ne 0 ]; then
		echo "{\"status\": \"ERR\", \"msg\": \"failed to put slab: $slab\"}"
		return 1
	fi
	echo "{\"status\": \"OK\", \"out_bytes\": $sz}"
	if [ ! -z "$inode" -a ! -z "$base" ]; then
		logger -i -t potatofs-backend -p user.info \
			"putting inode $inode / base $base"
	fi
}

mkdir -p $BACKEND_DATA_PATH

case $1 in
	df)
		do_df
		;;
	get)
		do_get
		;;
	put)
		do_put
		;;
	*)
		usage
		exit 2
esac

exit $?
