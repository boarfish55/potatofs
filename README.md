OVERVIEW
========
PotatoFS is a FUSE filesystem implementation that aims to to store data on
high-lacency backends, for instance one of the many cloud storage options.
It then uses local, lower-lacenty storage to cache data and perform I/O
operations on portions of cached data.

There are a few major goals PotatoFS is trying to achieve:

  1) Backend agnosticism:

     PotatoFS invokes external commands in order to retrieve or store
     data to the high-latency backends.

  2) Avoid reimplementing encryption and compression:

     PotatoFS should rely on external commands to compress and/or
     encrypt data before sending it to the backends. If local encryption
     is desired, it should be done at another layer, e.g. LUKS. External
     commands can also choose to implement some form predictive slab
     fetches based on past usage history (see backend_s3 for a
     simplistic approach).

  3) As a stretch goal, concurrent mounting:

     Multiple instances of PotatoFS should be able to mount the filesystem
     concurrently while preserving consistency. This would be achieved by
     having the PotatoFS instances communicate with one another.

Non-goals:

  1) Portability. Though I would like this to work on all BSDs, there is
     a dependency on low-level FUSE, which not all BSDs support.
     On-disk format is architecture-dependent.

  2) Disaster recovery. PotatoFS may not sync local slabs to the high-latency
     backend on a frequent basis. Therefore, local storage should still be
     reliable and persistent. This is especially true for inode table slabs,
     since we defer closing those slabs until there are no inodes with a
     non-zero lookup count (see FUSE low-level docs). This may be improved a
     bit in the future (possibly by snapshotting inode tables in a
     consistent state).

Author: Pascal Lalonde <plalonde@overnet.ca>

See the COPYING file for licensing information.

DISCLAIMER
==========
PotatoFS hasn't seen widespread use and testing. Like any filesystem
with little testing, data loss and/or corruption may occur. Use at your
own risk.

INSTALLATION & USAGE
====================

Dependencies / license (not including backends):
- pkg-config
- libuuid (BSD-3)
- libfuse (LGPL-2)
- libbsd-dev (BSD-3, BSD-2, Expat)
- sqlite3 (public domain)
- zlib (zlib)
- libjansson-dev >= 2.9 (Expat)

Recommended:
- jq (for sample backends)


```
$ make
```

Then, create yourself a partition (or use an existing one, though this is not
recommended), typically /var/potatofs. Grant the user who will mount this
filesystem access to that partition:

```
# mkdir /var/potatofs
# chown <uid>:<gid> /var/potatofs
```

You'll need to select a backend and tweak your configuration file. Look
at the example backends to see how to come up with your own. Essentially a
backend script needs to support the `get`, `put`, `hint` and `df`
commands and return specific error codes. The `backends/backend_cp.sh` script
is the simplest one to use as a starting point. See also the
`potatofs-backend(7)` manpage.

Then you'll need to put the configuration file somewhere and adjust the
backend's path and data path. See `potatofs.conf.sample` for an example
configuration. You can install it as `/etc/potatofs.conf` or use the
`cfg_path` mount option to provide an alternate path.

Once all this is done, create an entry in your fstab:

```
/path/to/bin/potatofs /mnt/potatofs fuse noauto,nofail,_netdev,user,cfg_path=/path/to/potatofs/config 0 0
```

Then mount it:

```
$ mount /mnt/potatofs
```

Client applications may receive some unexpected errno codes in case of error,
specific to how potatofs operates:

* EIO for any unrecoverable error dealing with data corruption
* ENOMEDIUM for all retryable errors, such as if the backend script times out,
  fails or if some flock() contention happens on local slabs. Note that
  ENOMEDIUM is only ever returned if the user requested that the FS be put in
  "offline" mode. By default we try to ensure data integrity by retrying those
  operations forever. But if a user expects things to be stalled for a long
  time (e.g. no network), setting offline mode can let potatofs return this
  error while trying to preserve data integrity. Note that this failure mode is
  not well tested.
* EINTR, similar to ENOMEDIUM, is returned when SIGINT is sent to a process
  that is stuck retrying "retryable" operations. This relies on FUSE
  properly sending an INTERRUPT for all blocked file operations from the
  signaled process.
* ENOMEM for some operations that need heap memory to perform their task.
  While this is to be normally expected from open() for example, some other
  calls such as write() would normally never return ENOMEM. But here they can.
  This is however unlikely to happen unless we are dealing with a very, very
  large amount of inodes open in memory.


DESIGN NOTES
============
We use FUSE multithreading and splicing, however no writeback since we plan on
allowing multiple writers, eventually.
See: https://marc.info/?l=fuse-devel&m=150640983731277&w=2

	"This mode assumes that all changes to the filesystem go through the
	FUSE kernel module (size and atime/ctime/mtime attributes are kept
	up-to-date by the kernel), so it's generally not suitable for network
	filesystems."

Currently the filesystem uses O_SYNC for directory data and inode tables.
Maybe one day we can add journaling.

Inode struct is 4K. The reasoning behind this is that since we expect the
backend to be *really* slow, we want to get the most of our fetching slabs.
With the default values, inode tables can store 2048 inodes, and their first
~3.5K of data is stored directly in the inode, meaning small directories and
small files require no further download from the backend. This should make
directory listing and things like 'head' or 'file', or 'grep' on small text
files to proceed quickly enough. Doing a bit of stats on my own home
directory, a large majority of files are under 4K in size.


KNOWN ISSUES
============
* When potatoctl fsck errors out, it may not always shutdown the mgr.
* Running in low-space conditions isn't well tested. Corruption may occur.

TODO
====
* Retryable failures are not well tested or even supported in many
  dirinode operations. Need to review the failure path in each of the
  fs_* functions. What may be best is to wrap each such function
  into another one that handles retries and cancelations. This may need
  to be done alongside the ops queue refactor described below. At the moment,
  most read-only operations should be safe, though this is not thoroughly
  verified.
* Refactor fuse ops handling as a queue so we can implement nice things
  like interrupting in flight operations, or journaling.
* Add a potatoctl backup command, which does an online backup of the
  slab db, uploads it to the backend, as well as the stats fs_info file.
  See: https://www.sqlite.org/backup.html
* fsck doesn't seem to detect all cases of lost directories and files. For
  example:
  - Leaving an unreferenced directory with nlink 1.
  - nlink count on a directory based on how many child directories there are.
* Add a test to try out the last possible inode, 2^63
* Investigate whether it's possible to exploit a race condition in
  unlink/truncate to read previous file data.
* Add a "rm" handler in backend scripts, though mention this will only
  be used by fsck, therefore is optional.
* fsck should cleanup unreferenced slabs on the backend.
* potatoctl's code is generally pretty ugly. Needs some cleanup. Tests too.
