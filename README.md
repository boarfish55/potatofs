DISCLAIMER
==========
This is a work in progress. Expect poor performance and possible data
corruption. Do not use to store anything you're not prepared to lose!


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
     is desired, it should be done at another layer, e.g. LUKS, or a
     stackable filesystem.

  3) As a stretch goal, concurrent mounting:

     Multiple instances of PotatoFS should be able to mount the filesystem
     concurrently while preserving consistency. This would be achieved by
     having the PotatoFS instances communicate with one another.

Non-goals:

  1) Portability. Though I would like this to work on all BSDs, there is
     a dependency on low-level FUSE, which not all BSDs support. We
     currently don't care about endianness. On-disk format is
     platform-dependent. Maybe one day we'll care and do all the
     byte-swapping, though it's unsure how that would affect performance.

  2) Disaster recovery. PotatoFS may not sync local slabs to the high-latency
     backend on a frequent basis. Therefore, local storage should still be
     reliable and persistent. This is especially true for inode table slabs,
     since we defer closing those slabs until there are no inodes with a
     non-zero lookup count (see FUSE low-level docs). This may be improved a
     bit in the future (possibly by snapshotting inode tables in a
     consistent state).

  3) Find a cool unique name. Finding a free 5-letter acronym ending in
     "-FS" is next to impossible these days:

     So meet PotatoFS. Potatoes are nourishing and can easily complement
     a wide variety of dishes.


Author: Pascal Lalonde <plalonde@overnet.ca>

See the COPYING file for licensing information.

Dependencies / license (not including backends):
- pkg-config
- libuuid (BSD-3)
- libfuse (LGPL-2)
- libbsd-dev (BSD-3, BSD-2, Expat)
- sqlite3 (public domain)
- zlib (zlib)
- libjansson-dev >= 2.9 (Expat)


INSTALLATION & USAGE
====================

```
$ make
```

Then, create yourself a partition (or use an existing one, though this is not
recommended), typically /var/potatofs. Grant the user who will mount this
filesystem access to that partition. An example init script is provided.

You'll need to select a backend and tweak your configuration file. Look
at the example backends to see how to come up with your own. Essentially a
backend script needs to support the `get`, `put` and `df` commands and return
specific error codes. The `backend_cp.sh` script is the simplest one to
use as a starting point.

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


DESIGN NOTES
============
We should be able to use FUSE multithreading and splicing, however no
writeback since we plan on allowing multiple writers, eventually.
See: https://marc.info/?l=fuse-devel&m=150640983731277&w=2

	"This mode assumes that all changes to the filesystem go through the
	FUSE kernel module (size and atime/ctime/mtime attributes are kept
	up-to-date by the kernel), so it's generally not suitable for network
	filesystems."

Currently the filesystem uses O_SYNC for directory data and inode tables.
Maybe one day we can add journaling or soft updates.

Inode struct is 4K. The reasoning behind this is that since we expect the
backend to be *really* slow, we want to get the most of our fetching slabs.
With the default values, inode tables can store 2048 inodes, and their first
~4K of data is stored directly in the inode, meaning small directories and
small files require no further download from the backend. This should make
directory listing and things like 'head' or 'file', or 'grep' on small text
files to proceed quickly enough. Doing a bit of stats on my own home
directory, a large majority of files are under 4K in size.

Directory entries are currently a fixed size, with 255 bytes reserved for
file names. This is not ideal, and someday I might go back and handle
variable-sized records for filenames.


KNOWN ISSUES
============

* If the backend were to become unavailable (or the transport, i.e. Internet),
  most likely I/O operations would stall in 'D' state, with no way to
  recover until the backend is available again. Error handling in these
  situations is questionable at best and needs to be reviewed. We can't
  properly interrupt I/O ops in flight at this time.
* When downloading from the backend (slab_load()), we hold the slab
  lock the entire time, meaning we can't do anything. We might have to
  queue slab downloads without holding the lock?? Or maybe read lock?
  Then upgrade to a write lock when the slab is local.
* When potatoctl fsck errors out, it may not always shutdown the mgr.

TODO
====
* On install, we should have mount.potatofs and fsck.potatofs binaries,
  even if only symlinked.
* Memory-bound our stuff. open() is allowed to return ENOMEM, so we can
  actually cap how many open inodes we have at once. We should return
  ENOMEM as XLOG_FS.
* Make directory lookups faster; too slow on large directories
* fsck doesn't seem to detect all cases of lost directories and files. For
  example:
  - Leaving an unreferenced directory with nlink 1.
  - nlink count on a directory based on how many child directories there are.
* All the fuse fs_ functions will need to handle backend timeouts gracefully
  and bubble up a nicer error to processes. They should retry the operations
  but check for interrupt in-between with fuse_req_interrupted(req).
  Claim errors that we could loop until interrupt:
  - XLOG_APP, XLOG_BEERROR (Internet?)
  - XLOG_APP, XLOG_BETIMEOUT (Internet?)
  - XLOG_ERRNO, ENOSPC (no space on cache, copy_incoming_slab, claim, new slab)
  - XLOG_APP, XLOG_BUSY (deadlock?; should not happen unless an external program
    is holding a lock; retryable)
  - XLOG_APP, XLOG_MISMATCH (eventual consistency)
  - XLOG_APP, XLOG_NOSLAB (Eventual consistency)
* Add a test to try out the last possible inode, 2^63
* Investigate whether it's possible to exploit a race condition in
  unlink/truncate to read previous file data.
* In low-space conditions, run flush/purge more often to free up space. The
  problem is that it also clogs up the workers. Maybe we need an separate
  control socket that's used by non-workers. Would also solve the
  potatoctl claim vs. fs deadlock.
* Add a "rm" handler in backend scripts, though mention this will only
  be used by fsck, therefore is optional.
* Add a "wide" option to top
* fsck should cleanup unreferenced slabs on the backend.
* Add a way for potatoctl to dump inode fields in JSON, such as to list
  all entries in a directory, or the size of an inode. Useful to
  to do manual claims and all.
* potatoctl's code is generally pretty ugly. Needs some cleanup. Tests too.
* Need to doublecheck all the usage and conversions for ino_t (uint64_t)
  and off_t (int64_t), blkcnt_t (int64_t).
* Some format strings have the wrong conversion for tv_nsec, should be "l".
* Refactor de fuse ops handling as a queue so we can implement nice things
  like interrupting in flight operations, or journaling/soft updates.
