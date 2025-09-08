#!/bin/sh

set -e

cmd="$1"

cur=$(git describe --abbrev=0)
cur=${cur#v}

slab_version=$(egrep "^#define +SLAB_VERSION +[0-9]+" slabs.h | awk '{print $3}')
slabdb_version=$(egrep "^#define +SLABDB_VERSION +[0-9]+" slabdb.h | awk '{print $3}')
dirinode_format=$(egrep "^#define +DIRINODE_FORMAT +[0-9]+" dirinodes.h | awk '{print $3}')

# We subtract 5 to avoid a big version jump since starting to use this script
major=$(($slab_version + $slabdb_version + $dirinode_format - 5))
minor=$(echo $cur | cut -d. -f 2)
patch=$(echo $cur | cut -d. -f 3)

if [ "$major" -gt "$(echo $cur | cut -d. -f 1)" ]; then
	minor=0
	patch=0
else
	case $cmd in
		major)
			echo "$(basename $0): no changes that require a major version"
			exit 1
			;;
		minor)
			minor=$(($minor + 1))
			patch=0
			;;
		patch)
			patch=$(($patch + 1))
			;;
		*)
			echo "Usage: $(basename $0) <major|minor|patch>"
			exit 2
			;;
	esac
fi

echo "$cur => $major.$minor.$patch"

read -p "Tag it? (y/N) " RESP

if [ "$RESP" = "y" -o "$RESP" = "Y" ]; then
	sed -i "s/^#define VERSION \".*\"$/#define VERSION \"$major.$minor.$patch\"/" version.h
	git add version.h
	git commit -m "$major.$minor.$patch"
	git tag -m "v$major.$minor.$patch" "$major.$minor.$patch"
fi

exit 0
