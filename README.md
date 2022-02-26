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

  2) Find a cool unique name. Finding a free 5-letter acronym ending in
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
- liblmdb (OpenLDAP)
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
`POTATOFS_CONFIG` environment variable to provide an alternate path, or
use the `-c` command line flag.

Once all this is done:

```
$ ./potatofs.init start
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

* During testing under low-space situations on the cache partition I've
  hit some corruption/deadlock issue. Though some safeguards were added, it
  wasn't fully root caused yet and therefore it's safer to make sure space
  is never low.
* If the backend were to become unavailable (or the transport, i.e. Internet),
  most likely I/O operations would stall in 'D' state, with no way to
  recover until the backend is available again. Error handling in these
  situations is questionable at best and needs to be reviewed. We can't
  properly interrupt I/O ops in flight at this time.


TODO
====

* Make the workers and timeouts configurable in the config file
* Add a test for unlink on large file; resulting slabs should be
  truncated.
* Add validation in config_read, right now even if we point it at a dir
  it just silently works.
* In low-space conditions, run flush/purge more often to free up space. The
  problem is that is also clogs up the workers. Maybe we need an separate
  control socket that's used by non-workers. Would also solve the
  potatoctl claim vs. fs deadlock.
* Don't put backend get/put args on the command line, for security reasons.
  Pass to stdin in JSON instead (one line). Add warning in backend cp/scp
  about the fact that those leak the slab names in the ps output and it's
  better to use something other than shell scripts.
* Add a "rm" handler in backend scritps, though mention this will only
  be used by fsck, therefore is optional.
* Add a "wide" option to top
* Doublecheck that atime is working as intended, add a test
* Have fsck verify the slabdb too; the db must match the actual slabs.
* Purging also needs to cleanup the backend of unreferenced slabs? Or
  maybe just fsck.
* Add a way for potatoctl to dump inode fields in JSON, such as to list
  all entries in a directory, or the size of an inode. Useful to
  to do manual claims and all.
* potatoctl's code is generally pretty ugly. Needs some cleanup. Tests too.
* exlog (possibly renaming to xlog) needs to cleanup in how calls are made
  and also how we have to clear the error in many places. Also we should
  add a descriptive text to the contextual errors instead of just printing
  the index. Also, instead of doing exlog_zerr() all over the place,
  simply do it directly inside function args since it returns the struct
  it just cleared. This way we ensure users already clear it.
* Refactor de fuse ops handling as a queue so we can implement nice things
  like interrupting in flight operations, or journaling/soft updates.
