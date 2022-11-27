#!/bin/bash
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


# The primary backend will be used to get/df commands, put is sent to all.
primary_backend="$HOME/.potatofs/backends/backend1.sh"
secondary_backend="$HOME/.potatofs/backends/backend2.sh"

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
	echo "       $(basename $0) hint"
	echo ""
	echo "           Output is a JSON string with the following format:"
	echo ""
	echo "           {\"status\": \"OK\"}"
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

do_hint() {
	exec $primary_backend hint
}

do_df() {
	# It would be best to get the size of both backends and use the
	# lowest value to be safe.
	exec $primary_backend df
}

do_get() {
	exec $primary_backend get
}

do_put() {
	tee >($primary_backend put > $primary_output) \
		>($secondary_backend put > $secondary_output) >/dev/null

	wait

	if [[ ! -s "$primary_output" || ! -s "$secondary_output" ]]; then
		echo "{\"status\": \"ERR\", \"msg\": \"bad invocation\"}"
		return 2
	fi

	if [[ "`cat $primary_output | jq -r .status`" != "OK" ]]; then
		cat $primary_output
		return 1
	elif [[ "`cat $secondary_output | jq -r .status`" != "OK" ]]; then
		cat $secondary_output
		return 1
	fi
	cat $primary_output
}

case $1 in
	df)
		do_df
		;;
	hint)
		do_hint
		;;
	get)
		do_get
		;;
	put)
		primary_output=$(mktemp -t "multi_backend.XXXXXX")
		secondary_output=$(mktemp -t "multi_backend.XXXXXX")
		do_put
		rm -f $primary_output $secondary_output
		;;
	*)
		usage
		exit 2
esac

exit $?
