#!/bin/bash

# See here:
#   https://developers.google.com/identity/protocols/oauth2/limited-input-device

creds=$HOME/potatofs/drive_creds
client_id=$(cat $creds | jq -r .installed.client_id)
client_secret=$(cat $creds | jq -r .installed.client_secret)
refresh_token=$(cat $HOME/potatofs/drive_refresh_token)
token_path=$HOME/potatofs/drive_token
folder_id_path=$HOME/potatofs/folder_id
curlrc_head=$HOME/potatofs/curlrc.head

# The folder ID woud not normally change. This could be "hardcoded" here to avoid
# an extra lookup.
drive_folder="potatofs"
passphrase="$HOME/potatofs/secret"

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

fail() {
	msg="$1"
	err="${2:-ERR}"
	echo "{\"status\": \"$err\", \"msg\": \"$msg\"}"
	exit 1
}

fail_cmd() {
	echo "{\"status\": \"$err\", \"msg\": \"bad invocation\"}"
	exit 2
}

new_folder() {
	f="$1"
	data="{\"name\": \"$f\", \"mimeType\": \"application/vnd.google-apps.folder\"}"
	sz=$(echo -n $data | wc -c)
	curl -K $curlrc_head \
		-H "Content-Type: application/json" \
		-H "Content-Length: $sz" \
		-d "$data" \
		"https://www.googleapis.com/drive/v3/files"
}

find_file() {
	parent="$1"
	name="$2"
	curl -K $curlrc_head \
		-G --data-urlencode "q=name=\"$2\" and \"$parent\" in parents and trashed=false" \
		https://www.googleapis.com/drive/v3/files | jq -r .files[].id
}

upload_resumable() {
	parent="$1"
	src="$2"
	name="$3"

	if [ -z "parent" -o ! -r "$src" -o -z "$name" ]; then
		fail_cmd
	fi

	id=$(find_file $parent "$name.crypt")

	if [ -z "$id" ]; then
		method="POST"
		data="{\"name\": \"$name.crypt\", \"parents\": [\"$parent\"]}"
		url="https://www.googleapis.com/upload/drive/v3/files?uploadType=resumable"
	else
		method="PATCH"
		data="{}"
		url="https://www.googleapis.com/upload/drive/v3/files/$id?uploadType=resumable"
	fi

	tmp=$(mktemp /dev/shm/backend_gdrive_curl.XXXXXX)
	sz=$(echo -n $data | wc -c)
	curl -K $curlrc_head -D $tmp -X $method \
		-H "Content-Type: application/json; charset=UTF-8" \
		-H "Content-Length: $sz" \
		-d "$data" \
		$url
	if [ $? -ne 0 ]; then
		fail "curl failed with code $?"
	fi
	location=$(egrep -i '^location: ' $tmp | cut -d' ' -f 2)
	if [ -z "$location" ]; then
		fail "curl: no location header back from gdrive"
	fi
	echo "url = $location" > $tmp

	sz=$(stat -c %s $src)
	out=$(cat $src | \
		gzip -c | \
		openssl enc -aes256 -pbkdf2 -pass file:$passphrase -e | \
		curl -K $curlrc_head -X PUT -o /dev/null \
		-w '%{http_code}:%{size_upload}\n' \
		--data-binary @- \
		-H "Content-Type: application/octet-stream" \
		-K $tmp)
	rm $tmp
	if [ "${out%%:*}" != "200" ]; then
		fail "curl: error ${out%%:*} during PUT"
	fi
	echo "{\"status\": \"OK\", \"out_bytes\": ${out##*:}}"
}

get_file() {
	parent="$1"
	name="$2"
	dest="$3"
	inode="$4"
	base="$5"

	if [ -z "parent" -o -z "$name" -o -z "$dest" ]; then
		fail_cmd
	fi

	id=$(find_file $parent "$name.crypt")
	if [ -z "$id" ]; then
		echo "{\"status\": \"ERR_NOENT\", \"msg\": \"no such file\"}"
		exit 1
	fi

	tmp=$(mktemp /dev/shm/backend_gdrive_curl.XXXXXX)
	curl -K $curlrc_head -o - -w '%{stderr}%{json}\n' \
		https://www.googleapis.com/drive/v3/files/$id?alt=media 2> $tmp | \
		openssl enc -aes256 -pbkdf2 -pass file:$passphrase -d | \
		gunzip -c > $dest
	http_code=$(cat $tmp | jq .http_code)
	sz=$(cat $tmp | jq .size_download)
	rm $tmp
	if [ "$http_code" != "200" ]; then
		fail "curl: error ${out%%:*} during GET"
	fi
	echo "{\"status\": \"OK\", \"in_bytes\": $sz}"
	if [ ! -z "$inode" -a ! -z "$base" ]; then
		logger -i -t potatofs-backend -p user.info \
			"getting inode $inode / base $base"
	fi
}

list_files() {
	curl -K $curlrc_head \
		-G --data-urlencode "q=trashed=false" \
		https://www.googleapis.com/drive/v3/files
}

find_folder() {
	id="$1"
	curl -K $curlrc_head \
		-G --data-urlencode "q=name=\"$1\" and mimeType=\"application/vnd.google-apps.folder\"" \
		https://www.googleapis.com/drive/v3/files | jq -r .files[].id
}

do_df() {
	j=$(curl -K $curlrc_head \
		-G --data-urlencode "fields=storageQuota" \
		https://www.googleapis.com/drive/v3/about)
	total=$(echo $j | jq -r .storageQuota.limit)
	used=$(echo $j | jq -r .storageQuota.usage)
	echo "{\"status\": \"OK\", \"used_bytes\": $used, \"total_bytes\": $total}"
}

get_token() {
	refresh=false
	if [ -r $token_path ]; then
		mtime=$(stat -c %Y $token_path)
		now=$(date +%s)
		if [ $(((now - mtime) + 60)) -ge $(cat $token_path | jq .expires_in) ]; then
			refresh=true
		fi
	else
		touch $token_path
		chmod 600 $token_path
		refresh=true
	fi

	if $refresh; then
		curl -s -o $token_path \
			-d "client_id=$client_id&client_secret=$client_secret&refresh_token=$refresh_token&grant_type=refresh_token" \
			https://oauth2.googleapis.com/token
	fi
	tmp=$(mktemp /dev/shm/curlrc.head.XXXXXX)
	echo "-L" > $tmp
	echo "-s" >> $tmp
	echo -n "header = \"Authorization: Bearer " >> $tmp
	cat $token_path | jq -j .access_token >> $tmp
	echo '"' >> $tmp
	mv $tmp $curlrc_head
}

get_folder_id() {
	if [ ! -r $folder_id_path ]; then
		find_folder $drive_folder > $folder_id_path
	fi
	cat $folder_id_path
}

cmd="$1"

case $cmd in
	df)
		get_token
		do_df
		;;
	get)
		get_token
		# parent, name, dest
		get_file $(get_folder_id) $2 $3 $4 $5
		;;
	put)
		get_token
		# parent, src, name
		upload_resumable $(get_folder_id) $2 $3
		;;
	*)
		usage
		exit 1
		;;
esac

exit $?
