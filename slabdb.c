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

#include <errno.h>
#include <stdio.h>
#include <sqlite3.h>
#include <string.h>
#include <stdlib.h>
#include <uuid/uuid.h>
#include "slabdb.h"

/*
 * ATTENTION: sqlite3 does not technically support unsigned int64, only
 * the signed int64. However, we still store uint64 in many of the fields.
 * This is fine with type casting as long as we don't expect sqlite to be
 * able to successfully perform comparisons on the larger values in those
 * columns. Therefore, many case must be taken when writing queries that
 * deal with those columns.
 */

static uuid_t   instance_id;
static sqlite3 *db;
static int      db_version = 0;

const int   qry_busy_timeout = 15000;

const char *qry_create_version_table = "create table if not exists version"
	        " as select " SLABDB_VERSION " as version";
const char *qry_check_version = "select version from version";

const char *qry_create_table = "create table if not exists slabs("
	        "ino int not null, "
	        "base int not null, "
	        "revision int not null, "
	        "header_crc int not null, "
	        "owner blob, "
	        "last_claimed_sec int not null, "
	        "last_claimed_nsec int not null, "
	        "flags int not null, "
	        "truncate_offset int not null, "
	        "primary key(ino, base))";
const char *qry_create_index = "create index if not exists by_last_claimed on "
	        "slabs (last_claimed_sec, last_claimed_nsec asc)";

struct {
	sqlite3_stmt *stmt;
	char         *sql;
	int           i_ino;
	int           i_base;
	int           i_revision;
	int           i_header_crc;
	int           i_owner;
	int           i_last_claimed_sec;
	int           i_last_claimed_nsec;
	int           i_flags;
	int           i_truncate_offset;
} qry_put = {
	NULL,
	"insert or replace into slabs(ino, base, revision, header_crc, "
	    "owner, last_claimed_sec, last_claimed_nsec, flags, "
	    "truncate_offset) "
	    "values (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
	1, 2, 3, 4, 5, 6, 7, 8, 9
};

struct {
	sqlite3_stmt *stmt;
	char         *sql;
	int           i_ino;
	int           i_base;
	int           o_ino;
	int           o_base;
	int           o_revision;
	int           o_header_crc;
	int           o_owner;
	int           o_last_claimed_sec;
	int           o_last_claimed_nsec;
	int           o_flags;
	int           o_truncate_offset;
} qry_get = {
	NULL,
	"select ino, base, revision, header_crc, owner, "
	    "last_claimed_sec, last_claimed_nsec, flags, truncate_offset "
	    "from slabs where ino = ?1 and base = ?2",
	1, 2, 0, 1, 2, 3, 4, 5, 6, 7, 8
};

struct {
	sqlite3_stmt *stmt;
	char         *sql;
	int           i_base;
	int           o_base;
} qry_get_next_itbl = {
	NULL,
	"select base from slabs where ino = 0 and base > ?1 "
	    "order by ino, base limit 1",
	1, 0
};

struct {
	sqlite3_stmt *stmt;
	char         *sql;
	int           o_ino;
	int           o_base;
	int           o_revision;
	int           o_header_crc;
	int           o_owner;
	int           o_last_claimed_sec;
	int           o_last_claimed_nsec;
	int           o_flags;
	int           o_truncate_offset;
} qry_loop_lru = {
	NULL,
	"select ino, base, revision, header_crc, owner, "
	    "last_claimed_sec, last_claimed_nsec, "
	    "flags, truncate_offset from slabs "
	    "order by last_claimed_sec, last_claimed_nsec asc",
	0, 1, 2, 3, 4, 5, 6, 7, 8
};

struct {
	sqlite3_stmt    *stmt;
	char            *sql;
	struct timespec  start;
} qry_begin_txn = {
	NULL,
	"begin exclusive transaction"
};

struct {
	sqlite3_stmt *stmt;
	char         *sql;
} qry_commit_txn = {
	NULL,
	"commit"
};

struct {
	sqlite3_stmt *stmt;
	char         *sql;
} qry_rollback_txn = {
	NULL,
	"rollback"
};

struct {
	sqlite3_stmt *stmt;
	char         *sql;
	int           o_count;
} qry_count = {
	NULL,
	"select count(*) from slabs",
	0
};

static int
slabdb_qry_cleanup(sqlite3_stmt *stmt, struct xerr *e)
{
	int r;
	if ((r = sqlite3_reset(stmt)))
		return XERRF(e, XLOG_DB, r,
		    "sqlite3_reset: %s", sqlite3_errmsg(db));
	if ((r = sqlite3_clear_bindings(stmt)))
		return XERRF(e, XLOG_DB, r,
		    "sqlite3_clear_bindings: %s (%d)", sqlite3_errmsg(db), r);
	return 0;
}

int
slabdb_put_nolock(const struct slab_key *sk, struct slabdb_val *v,
    struct xerr *e)
{
	int         r;
	struct xerr e2;

	if ((r = sqlite3_bind_int64(qry_put.stmt, qry_put.i_ino, sk->ino)) ||
	    (r = sqlite3_bind_int64(qry_put.stmt, qry_put.i_base, sk->base)) ||
	    (r = sqlite3_bind_int64(qry_put.stmt,
	    qry_put.i_revision, v->revision)) ||
	    (r = sqlite3_bind_int(qry_put.stmt,
	    qry_put.i_header_crc, v->header_crc)) ||
	    (r = sqlite3_bind_int64(qry_put.stmt,
	    qry_put.i_last_claimed_sec, v->last_claimed.tv_sec)) ||
	    (r = sqlite3_bind_int64(qry_put.stmt,
	    qry_put.i_last_claimed_nsec, v->last_claimed.tv_nsec)) ||
	    (r = sqlite3_bind_int(qry_put.stmt, qry_put.i_flags, v->flags)) ||
	    (r = sqlite3_bind_int64(qry_put.stmt,
	    qry_put.i_truncate_offset, v->truncate_offset))) {
		XERRF(e, XLOG_DB, r,
		    "sqlite3_bind_int/int64: %s", sqlite3_errmsg(db));
		goto fail;
	}

	if ((r = sqlite3_bind_blob(qry_put.stmt, qry_put.i_owner, v->owner,
	    sizeof(uuid_t), SQLITE_STATIC))) {
		XERRF(e, XLOG_DB, r, "sqlite3_bind_blob: %s",
		    sqlite3_errmsg(db));
		goto fail;
	}

	switch (sqlite3_step(qry_put.stmt)) {
	case SQLITE_DONE:
		/* Nothing */
		break;
	case SQLITE_BUSY:
		XERRF(e, XLOG_APP, XLOG_BUSY, "sqlite3_step");
		goto fail;
	case SQLITE_MISUSE:
	case SQLITE_ERROR:
	default:
		XERRF(e, XLOG_DB, r, "sqlite3_step: %s",
		    sqlite3_errmsg(db));
		goto fail;
	}

	return slabdb_qry_cleanup(qry_put.stmt, e);
fail:
	if (slabdb_qry_cleanup(qry_put.stmt, xerrz(&e2)) == -1)
		xlog(LOG_ERR, &e2, "%s", __func__);
	return -1;
}

/*
 * If v->last_claimed is NULL, we just write back the previous value.
 */
int
slabdb_put(const struct slab_key *sk, struct slabdb_val *v, uint8_t flags,
    struct xerr *e)
{
	struct xerr       e2;
	struct slabdb_val r_v;

	if (slabdb_begin_txn(e) == -1)
		goto fail;

	if (slabdb_get_nolock(sk, &r_v, e) == -1)
		goto fail;

	if (
	    ((flags & SLABDB_PUT_REVISION) &&
	     r_v.revision == v->revision) &&

	    ((flags & SLABDB_PUT_HEADER_CRC) &&
	     r_v.header_crc == v->header_crc) &&

	    ((flags & SLABDB_PUT_OWNER) &&
	     uuid_compare(r_v.owner, v->owner) == 0) &&

	    ((flags & SLABDB_PUT_LAST_CLAIMED) &&
	     memcmp(&r_v.last_claimed, &v->last_claimed,
	     sizeof(struct timespec) == 0)) &&

	    ((flags & SLABDB_PUT_TRUNCATE) &&
	     ((r_v.flags & SLABDB_FLAG_TRUNCATE) ==
	     (v->flags & SLABDB_FLAG_TRUNCATE)) &&
	     (r_v.truncate_offset == v->truncate_offset))) {

		/* Same value, no need to update */
		if (slabdb_rollback_txn(xerrz(e)) == -1)
			return -1;
	} else {
		if (!(flags & SLABDB_PUT_REVISION))
			v->revision = r_v.revision;

		if (!(flags & SLABDB_PUT_HEADER_CRC))
			v->header_crc = r_v.header_crc;

		if (!(flags & SLABDB_PUT_OWNER))
			uuid_copy(v->owner, r_v.owner);

		if (!(flags & SLABDB_PUT_LAST_CLAIMED))
			memcpy(&v->last_claimed, &r_v.last_claimed, 
			    sizeof(struct timespec));

		if (!(flags & SLABDB_PUT_TRUNCATE)) {
			v->flags &= ~SLABDB_FLAG_TRUNCATE;
			v->flags |= (r_v.flags & SLABDB_FLAG_TRUNCATE);
			v->truncate_offset = r_v.truncate_offset;
		}

		if (slabdb_put_nolock(sk, v, e) == -1)
			goto fail;

		if (slabdb_commit_txn(e) == -1)
			goto fail;
	}

	return 0;
fail:
	if (slabdb_rollback_txn(xerrz(&e2)) == -1)
		xlog(LOG_ERR, &e2, "%s", __func__);
	return -1;
}

int
slabdb_get_nolock(const struct slab_key *sk, struct slabdb_val *v,
    struct xerr *e)
{
	int         r;
	struct xerr e2;

	if ((r = sqlite3_bind_int64(qry_get.stmt, qry_get.i_ino, sk->ino)) ||
	    (r = sqlite3_bind_int64(qry_get.stmt, qry_get.i_base, sk->base))) {
		XERRF(e, XLOG_DB, r, "sqlite3_bind_int64: %s",
		    sqlite3_errmsg(db));
		goto fail;
	}

	switch ((r = sqlite3_step(qry_get.stmt))) {
	case SQLITE_ROW:
		v->revision = (uint64_t)sqlite3_column_int64(qry_get.stmt,
		    qry_get.o_revision);
		v->header_crc = (uint32_t)sqlite3_column_int(qry_get.stmt,
		    qry_get.o_header_crc);
		v->last_claimed.tv_sec = sqlite3_column_int64(
		    qry_get.stmt, qry_get.o_last_claimed_sec);
		v->last_claimed.tv_nsec = sqlite3_column_int64(
		    qry_get.stmt, qry_get.o_last_claimed_nsec);
		v->flags = (uint32_t)sqlite3_column_int(qry_get.stmt,
		    qry_get.o_flags);
		v->truncate_offset = (uint64_t)sqlite3_column_int64(
		    qry_get.stmt, qry_get.o_truncate_offset);

		if (sqlite3_column_bytes(qry_get.stmt, qry_get.o_owner) == 0)
			uuid_clear(v->owner);
		else
			uuid_copy(v->owner,
			    sqlite3_column_blob(qry_get.stmt, qry_get.o_owner));
		break;
	case SQLITE_DONE:
		XERRF(e, XLOG_APP, XLOG_NOSLAB,
		    "sqlite3_step: slab not found, sk=%lu/%lu",
		    sk->ino, sk->base);
		goto fail;
	case SQLITE_BUSY:
		XERRF(e, XLOG_APP, XLOG_BUSY, "sqlite3_step");
		goto fail;
	case SQLITE_MISUSE:
	case SQLITE_ERROR:
	default:
		XERRF(e, XLOG_DB, r, "sqlite3_step: %s (%d)",
		    sqlite3_errmsg(db), r);
		goto fail;
	}

	return slabdb_qry_cleanup(qry_get.stmt, e);
fail:
	if (slabdb_qry_cleanup(qry_get.stmt, xerrz(&e2)) == -1)
		xlog(LOG_ERR, &e2, "%s", __func__);
	return -1;
}

/*
 * Get the revision, CRC and current owner of a slab; if the slab is not found
 * in the database (that is, it was never allocated), create an entry with
 * revision 0 to claim ownership.
 * TODO: Eventually this will involved consensus resolution as to who gets
 * ownership of the slab.
 */
int
slabdb_get(const struct slab_key *sk, struct slabdb_val *v, uint32_t oflags,
    struct xerr *e)
{
	char        u[37];
	struct xerr e2;

	if (slabdb_begin_txn(e) == -1)
		return -1;

	if (slabdb_get_nolock(sk, v, e) == -1) {
		if (!xerr_is(e, XLOG_APP, XLOG_NOSLAB) ||
		    (oflags & OSLAB_NOCREATE))
			goto fail;

		xerrz(e);
		v->revision = 0;
		v->header_crc = 0L;
		v->flags = 0;
		v->truncate_offset = 0;
		uuid_copy(v->owner, instance_id);
		if (clock_gettime(CLOCK_REALTIME, &v->last_claimed) == -1) {
			XERRF(e, XLOG_ERRNO, errno, "clock_gettime");
			goto fail;
		}
		if (slabdb_put_nolock(sk, v, e) == -1)
			goto fail;
		if (slabdb_commit_txn(e) == -1)
			goto fail;
	} else {
		// TODO: consensus resolution can happen here...
		if (uuid_compare(v->owner, instance_id) != 0) {
			uuid_unparse(v->owner, u);
			xlog_dbg(XLOG_SLABDB, "%s: changing ownership for "
			    "sk=%lu/%lu; previous=%s", __func__, sk->ino,
			    sk->base, u);
			uuid_copy(v->owner, instance_id);
			if (slabdb_put_nolock(sk, v, e) == -1)
				goto fail;
		}

		if (slabdb_commit_txn(e) == -1)
			goto fail;
	}

	uuid_unparse(v->owner, u);
	xlog_dbg(XLOG_SLABDB, "%s: k=%lu/%lu, v=%u/%lu/%s/%u.%u\n",
	    __func__,
	    sk->ino, sk->base, v->revision, v->header_crc, u,
	    v->last_claimed.tv_sec, v->last_claimed.tv_nsec);

	return 0;
fail:
	if (slabdb_rollback_txn(xerrz(&e2)) == -1)
		xlog(LOG_ERR, &e2, "%s", __func__);
	return -1;
}

int
slabdb_get_next_itbl(off_t *base, struct xerr *e)
{
	int         r;
	struct xerr e2;

	if ((r = sqlite3_bind_int64(qry_get_next_itbl.stmt,
	    qry_get_next_itbl.i_base, *base))) {
		XERRF(e, XLOG_DB, r, "sqlite3_bind_int64: %s",
		    sqlite3_errmsg(db));
		goto fail;
	}

	switch ((r = sqlite3_step(qry_get_next_itbl.stmt))) {
	case SQLITE_ROW:
		*base = sqlite3_column_int64(qry_get_next_itbl.stmt,
		    qry_get_next_itbl.o_base);
		break;
	case SQLITE_DONE:
		XERRF(e, XLOG_APP, XLOG_NOSLAB,
		    "sqlite3_step: no itbl found after base %lu", base);
		goto fail;
	case SQLITE_BUSY:
		XERRF(e, XLOG_APP, XLOG_BUSY, "sqlite3_step");
		goto fail;
	case SQLITE_MISUSE:
	case SQLITE_ERROR:
	default:
		XERRF(e, XLOG_DB, r, "sqlite3_step: %s (%d)",
		    sqlite3_errmsg(db), r);
		goto fail;
	}

	return slabdb_qry_cleanup(qry_get_next_itbl.stmt, e);
fail:
	if (slabdb_qry_cleanup(qry_get_next_itbl.stmt, xerrz(&e2)) == -1)
		xlog(LOG_ERR, &e2, "%s", __func__);
	return -1;
}

/*
 * The 'fn' function should return non-zero to stop iterating over entries.
 * This starts a transaction with a lock that's held until we are done
 * looping. Therefore fn should not start a transaction.
 */
int
slabdb_loop(int(*fn)(const struct slab_key *, const struct slabdb_val *,
    void *), void *data, struct xerr *e)
{
	int               r;
	struct slab_key   sk;
	struct slabdb_val v;
	struct xerr       e2;

	if (slabdb_begin_txn(e) == -1)
		return -1;

	while ((r = sqlite3_step(qry_loop_lru.stmt)) != SQLITE_DONE) {
		switch (r) {
		case SQLITE_ROW:
			sk.ino = (ino_t)sqlite3_column_int64(qry_loop_lru.stmt,
				qry_loop_lru.o_ino);
			sk.base = sqlite3_column_int64(qry_loop_lru.stmt,
				qry_loop_lru.o_base);
			v.revision = (uint64_t)sqlite3_column_int64(
			    qry_loop_lru.stmt, qry_loop_lru.o_revision);
			v.header_crc = (uint32_t)sqlite3_column_int(
			    qry_loop_lru.stmt, qry_loop_lru.o_header_crc);
			v.last_claimed.tv_sec = sqlite3_column_int64(
			    qry_loop_lru.stmt,
			    qry_loop_lru.o_last_claimed_sec);
			v.last_claimed.tv_nsec = sqlite3_column_int64(
			    qry_loop_lru.stmt,
			    qry_loop_lru.o_last_claimed_nsec);
			v.flags = sqlite3_column_int(
			    qry_loop_lru.stmt, qry_loop_lru.o_flags);
			v.truncate_offset = sqlite3_column_int64(
			    qry_loop_lru.stmt,
			    qry_loop_lru.o_truncate_offset);

			if (sqlite3_column_bytes(qry_loop_lru.stmt,
			    qry_loop_lru.o_owner) == 0) {
				uuid_clear(v.owner);
			} else {
				uuid_copy(v.owner,
				    sqlite3_column_blob(qry_loop_lru.stmt,
				    qry_loop_lru.o_owner));
			}
			if (fn(&sk, &v, data))
				goto end;
			break;
		case SQLITE_BUSY:
			XERRF(e, XLOG_APP, XLOG_BUSY, "sqlite3_step");
			goto fail;
		case SQLITE_MISUSE:
		case SQLITE_ERROR:
		default:
			XERRF(e, XLOG_DB, r, "sqlite3_step: %s (%d)",
			    sqlite3_errmsg(db), r);
			goto fail;
		}
	}

end:
	if (slabdb_commit_txn(&e2) == -1)
		goto fail;

	return slabdb_qry_cleanup(qry_loop_lru.stmt, e);
fail:
	if (slabdb_rollback_txn(xerrz(&e2)) == -1)
		xlog(LOG_ERR, &e2, "%s", __func__);
	if (slabdb_qry_cleanup(qry_loop_lru.stmt, xerrz(&e2)) == -1)
		xlog(LOG_ERR, &e2, "%s", __func__);
	return -1;
}

static time_t
txn_duration()
{
	time_t          delta_ns;
	struct timespec end;

	if (clock_gettime(CLOCK_REALTIME, &end) == -1) {
		xlog_strerror(LOG_ERR, errno, "%s: clock_gettime");
		return ULONG_MAX;
	}

	delta_ns = ((end.tv_sec * 1000000000) + end.tv_nsec) -
	    ((qry_begin_txn.start.tv_sec * 1000000000) +
	     qry_begin_txn.start.tv_nsec);
	return delta_ns;
}

int
slabdb_begin_txn(struct xerr *e)
{
	int         r;
	struct xerr e2;

	switch ((r = sqlite3_step(qry_begin_txn.stmt))) {
	case SQLITE_DONE:
		/* Nothing */
		break;
	case SQLITE_BUSY:
		XERRF(e, XLOG_APP, XLOG_BUSY, "sqlite3_step");
		goto fail;
	case SQLITE_MISUSE:
	case SQLITE_ERROR:
	default:
		XERRF(e, XLOG_DB, r, "sqlite3_step: %s (%d)",
		    sqlite3_errmsg(db), r);
		goto fail;
	}

	if (clock_gettime(CLOCK_REALTIME, &qry_begin_txn.start) == -1) {
		XERRF(e, XLOG_ERRNO, errno, "clock_gettime");
		goto fail;
	}
	return slabdb_qry_cleanup(qry_begin_txn.stmt, e);
fail:
	if (slabdb_qry_cleanup(qry_begin_txn.stmt, xerrz(&e2)) == -1)
		xlog(LOG_ERR, &e2, "%s", __func__);
	return -1;
}

int
slabdb_commit_txn(struct xerr *e)
{
	int         r;
	struct xerr e2;
	time_t      delta_ns;

	switch ((r = sqlite3_step(qry_commit_txn.stmt))) {
	case SQLITE_DONE:
		/* Nothing */
		break;
	case SQLITE_BUSY:
		XERRF(e, XLOG_APP, XLOG_BUSY, "sqlite3_step");
		goto fail;
	case SQLITE_MISUSE:
	case SQLITE_ERROR:
	default:
		XERRF(e, XLOG_DB, r, "sqlite3_step: %s (%d)",
		    sqlite3_errmsg(db), r);
		goto fail;
	}

	delta_ns = txn_duration();
	xlog_dbg(XLOG_SLABDB, "%s: transaction held the lock for %u.%09u "
	    "seconds", __func__, delta_ns / 1000000000, delta_ns % 1000000000);

	return slabdb_qry_cleanup(qry_commit_txn.stmt, e);
fail:
	// TODO: rollback?
	if (slabdb_qry_cleanup(qry_commit_txn.stmt, xerrz(&e2)) == -1)
		xlog(LOG_ERR, &e2, "%s", __func__);
	return -1;
}

int
slabdb_rollback_txn(struct xerr *e)
{
	int         r;
	struct xerr e2;
	time_t      delta_ns;

	switch ((r = sqlite3_step(qry_rollback_txn.stmt))) {
	case SQLITE_DONE:
		/* Nothing */
		break;
	case SQLITE_BUSY:
		XERRF(e, XLOG_APP, XLOG_BUSY, "sqlite3_step");
		goto fail;
	case SQLITE_MISUSE:
	case SQLITE_ERROR:
	default:
		XERRF(e, XLOG_DB, r, "sqlite3_step: %s (%d)",
		    sqlite3_errmsg(db), r);
		goto fail;
	}

	delta_ns = txn_duration();
	xlog_dbg(XLOG_SLABDB, "%s: transaction held the lock for %u.%09u "
	    "seconds", __func__, delta_ns / 1000000000, delta_ns % 1000000000);

	return slabdb_qry_cleanup(qry_rollback_txn.stmt, e);
fail:
	if (slabdb_qry_cleanup(qry_rollback_txn.stmt, xerrz(&e2)) == -1)
		xlog(LOG_ERR, &e2, "%s", __func__);
	return -1;
}

ssize_t
slabdb_count(struct xerr *e)
{
	int         r;
	struct xerr e2;
	ssize_t     count;

	switch ((r = sqlite3_step(qry_count.stmt))) {
	case SQLITE_ROW:
		count = sqlite3_column_int(qry_count.stmt, 0);
		break;
	case SQLITE_DONE:
		XERRF(e, XLOG_APP, XLOG_NOSLAB,
		    "sqlite3_step() returned no result");
		goto fail;
	case SQLITE_BUSY:
		XERRF(e, XLOG_APP, XLOG_BUSY, "sqlite3_step");
		goto fail;
	case SQLITE_MISUSE:
	case SQLITE_ERROR:
	default:
		XERRF(e, XLOG_DB, r, "sqlite3_step: %s (%d)",
		    sqlite3_errmsg(db), r);
		goto fail;
	}

	if (slabdb_qry_cleanup(qry_count.stmt, e) == -1)
		return -1;
	return count;
fail:
	if (slabdb_qry_cleanup(qry_count.stmt, xerrz(&e2)) == -1)
		xlog(LOG_ERR, &e2, "%s", __func__);
	return -1;
}

static int
slabdb_check_version(void *unused, int col_count, char **val, char **columns)
{
	int i;
	for (i = 0; i < col_count; i++) {
		if (strcmp(columns[i], "version") == 0 && val[i])
			db_version = atoi(val[i]);
	}
	return 0;
}

int
slabdb_init(uuid_t id, struct xerr *e)
{
	char path[PATH_MAX];
	int  r;

	uuid_copy(instance_id, id);

	if (snprintf(path, sizeof(path), "%s/%s", fs_config.data_dir,
	    DEFAULT_DB_NAME) >= sizeof(path))
		return XERRF(e, XLOG_APP, XLOG_NAMETOOLONG,
		    "db name too long");

	if ((r = sqlite3_open(path, &db)))
		return XERRF(e, XLOG_DB, r, "sqlite3_open: %s",
		    sqlite3_errmsg(db));

	// TODO: implement my own busy handler, with logging when we've
	// been waiting more than X seconds.
	if ((r = sqlite3_busy_timeout(db, 60000))) {
		XERRF(e, XLOG_DB, r, "sqlite3_busy_timeout: %s",
		    sqlite3_errmsg(db));
		goto fail;
	}

	if ((r = sqlite3_exec(db, qry_create_version_table, NULL, NULL, NULL))) {
		XERRF(e, XLOG_DB, r, "sqlite3_exec: %s", sqlite3_errmsg(db));
		goto fail;
	}

	if ((r = sqlite3_exec(db, qry_check_version, slabdb_check_version,
	    NULL, NULL))) {
		XERRF(e, XLOG_DB, r, "sqlite3_exec: %s", sqlite3_errmsg(db));
		goto fail;
	}

	if (db_version != atoi(SLABDB_VERSION)) {
		XERRF(e, XLOG_APP, XLOG_INVAL,
		    "mismatching db_version; current=%d, wanted=%d",
		    db_version, SLABDB_VERSION);
		goto fail;
	}

	if ((r = sqlite3_exec(db, qry_create_table, NULL, NULL, NULL))) {
		XERRF(e, XLOG_DB, r, "sqlite3_exec: %s", sqlite3_errmsg(db));
		goto fail;
	}

	if ((r = sqlite3_exec(db, qry_create_index, NULL, NULL, NULL))) {
		XERRF(e, XLOG_DB, r, "sqlite3_exec: %s", sqlite3_errmsg(db));
		goto fail;
	}

	if ((r = sqlite3_prepare_v2(db, qry_put.sql, -1,
	    &qry_put.stmt, NULL))) {
		XERRF(e, XLOG_DB, r, "sqlite3_prepare_v2: qry_put: %s",
		    sqlite3_errmsg(db));
		goto fail;
	}

	if ((r = sqlite3_prepare_v2(db, qry_get.sql, -1,
	    &qry_get.stmt, NULL))) {
		XERRF(e, XLOG_DB, r, "sqlite3_prepare_v2: qry_get: %s",
		    sqlite3_errmsg(db));
		goto fail;
	}

	if ((r = sqlite3_prepare_v2(db, qry_get_next_itbl.sql, -1,
	    &qry_get_next_itbl.stmt, NULL))) {
		XERRF(e, XLOG_DB, r,
		    "sqlite3_prepare_v2: qry_get_next_itbl: %s",
		    sqlite3_errmsg(db));
		goto fail;
	}

	if ((r = sqlite3_prepare_v2(db, qry_loop_lru.sql, -1,
	    &qry_loop_lru.stmt, NULL))) {
		XERRF(e, XLOG_DB, r, "sqlite3_prepare_v2: qry_loop_lru: %s",
		    sqlite3_errmsg(db));
		goto fail;
	}

	if ((r = sqlite3_prepare_v2(db, qry_begin_txn.sql, -1,
	    &qry_begin_txn.stmt, NULL))) {
		XERRF(e, XLOG_DB, r, "sqlite3_prepare_v2: qry_begin_txn: %s",
		    sqlite3_errmsg(db));
		goto fail;
	}

	if ((r = sqlite3_prepare_v2(db, qry_commit_txn.sql, -1,
	    &qry_commit_txn.stmt, NULL))) {
		XERRF(e, XLOG_DB, r, "sqlite3_prepare_v2: qry_commit_txn: %s",
		    sqlite3_errmsg(db));
		goto fail;
	}

	if ((r = sqlite3_prepare_v2(db, qry_rollback_txn.sql, -1,
	    &qry_rollback_txn.stmt, NULL))) {
		XERRF(e, XLOG_DB, r, "sqlite3_prepare_v2: qry_rollback_txn: %s",
		    sqlite3_errmsg(db));
		goto fail;
	}

	if ((r = sqlite3_prepare_v2(db, qry_count.sql, -1,
	    &qry_count.stmt, NULL))) {
		XERRF(e, XLOG_DB, r, "sqlite3_prepare_v2: qry_count: %s",
		    sqlite3_errmsg(db));
		goto fail;
	}

	return 0;
fail:
	sqlite3_close(db);
	return -1;
}

void
slabdb_shutdown()
{
	int r;

	if ((r = sqlite3_finalize(qry_put.stmt)))
		xlog(LOG_WARNING, NULL,
		    "%s: sqlite3_finalize: qry_put: %s", sqlite3_errmsg(db));

	if ((r = sqlite3_finalize(qry_get.stmt)))
		xlog(LOG_WARNING, NULL,
		    "%s: sqlite3_finalize: qry_get: %s", sqlite3_errmsg(db));

	if ((r = sqlite3_finalize(qry_get_next_itbl.stmt)))
		xlog(LOG_WARNING, NULL,
		    "%s: sqlite3_finalize: qry_get_next_itbl: %s",
		    sqlite3_errmsg(db));

	if ((r = sqlite3_finalize(qry_loop_lru.stmt)))
		xlog(LOG_WARNING, NULL,
		    "%s: sqlite3_finalize: qry_loop_lru: %s",
		    sqlite3_errmsg(db));

	if ((r = sqlite3_finalize(qry_begin_txn.stmt)))
		xlog(LOG_WARNING, NULL,
		    "%s: sqlite3_finalize: qry_begin_txn: %s",
		    sqlite3_errmsg(db));

	if ((r = sqlite3_finalize(qry_commit_txn.stmt)))
		xlog(LOG_WARNING, NULL,
		    "%s: sqlite3_finalize: qry_commit_txn: %s",
		    sqlite3_errmsg(db));

	if ((r = sqlite3_finalize(qry_rollback_txn.stmt)))
		xlog(LOG_WARNING, NULL,
		    "%s: sqlite3_finalize: qry_rollback_txn: %s",
		    sqlite3_errmsg(db));

	if ((r = sqlite3_finalize(qry_count.stmt)))
		xlog(LOG_WARNING, NULL,
		    "%s: sqlite3_finalize: qry_count: %s",
		    sqlite3_errmsg(db));

	if ((r = sqlite3_close(db)) != SQLITE_OK)
		xlog(LOG_ERR, NULL,
		    "%s: sqlite3_close: %s", sqlite3_errmsg(db));
}
