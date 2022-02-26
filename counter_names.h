/*
 *  Copyright (C) 2020-2022 Pascal Lalonde <plalonde@overnet.ca>
 *
 *  This file is part of PotatoFS, a FUSE filesystem implementation.
 *
 *  PotatoFS is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef COUNTER_NAMES_H
#define COUNTER_NAMES_H

const char *counter_names[] = {
	"fs_getattr",        /* COUNTER_FS_GETATTR */
	"fs_setattr",        /* COUNTER_FS_SETATTR */
	"fs_opendir",        /* COUNTER_FS_OPENDIR */
	"fs_readdir",        /* COUNTER_FS_READDIR */
	"fs_releasedir",     /* COUNTER_FS_RELEASEDIR */
	"fs_release",        /* COUNTER_FS_RELEASE */
	"fs_open",           /* COUNTER_FS_OPEN */
	"fs_read",           /* COUNTER_FS_READ */
	"fs_write",          /* COUNTER_FS_WRITE */
	"fs_flush",          /* COUNTER_FS_FLUSH */
	"fs_forget",         /* COUNTER_FS_FORGET */
	"fs_forget_multi",   /* COUNTER_FS_FORGET_MULTI */
	"fs_lookup",         /* COUNTER_FS_LOOKUP */
	"fs_mkdir",          /* COUNTER_FS_MKDIR */
	"fs_rmdir",          /* COUNTER_FS_RMDIR */
	"fs_unlink",         /* COUNTER_FS_UNLINK */
	"fs_statfs",         /* COUNTER_FS_STATFS */
	"fs_mknod",          /* COUNTER_FS_MKNOD */
	"fs_create",         /* COUNTER_FS_CREATE */
	"fs_fallocate",      /* COUNTER_FS_FALLOCATE */
	"fs_fsync",          /* COUNTER_FS_FSYNC */
	"fs_fsyncdir",       /* COUNTER_FS_FSYNCDIR */
	"fs_link",           /* COUNTER_FS_LINK */
	"fs_symlink",        /* COUNTER_FS_SYMLINK */
	"fs_readlink",       /* COUNTER_FS_READLINK */
	"fs_rename",         /* COUNTER_FS_RENAME */
	"fs_error",          /* COUNTER_FS_ERROR */
	"fs_n_open_slabs",   /* COUNTER_N_OPEN_SLABS */
	"fs_n_open_inodes",  /* COUNTER_N_OPEN_INODES */
	"fs_slabs_purged",   /* COUNTER_N_SLABS_PURGED */
	"fs_read_bytes",     /* COUNTER_READ_BYTES */
	"fs_write_bytes"     /* COUNTER_WRITE_BYTES */
};

const char *mgr_counter_names[] = {
	"backend_in_bytes",  /* COUNTER_BACKEND_IN_BYTES */
	"backend_out_bytes", /* COUNTER_BACKEND_OUT_BYTES */
	"slabs_purged"       /* MGR_COUNTER_SLABS_PURGED */

};

#endif
