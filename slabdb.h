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

#ifndef SLABDB_H
#define SLABDB_H

#include <stdint.h>
#include <uuid/uuid.h>
#include "xlog.h"
#include "slabs.h"

struct slabdb_val {
	uint64_t        revision;
	uint32_t        header_crc;
	uuid_t          owner;
	struct timespec last_claimed;
};

#define SLABDB_PUT_REVISION     0x01
#define SLABDB_PUT_HEADER_CRC   0x02
#define SLABDB_PUT_OWNER        0x04
#define SLABDB_PUT_LAST_CLAIMED 0x08
#define SLABDB_PUT_ALL          0xFF

int  slabdb_init(uuid_t, struct xerr *);
void slabdb_shutdown();

int slabdb_put(const struct slab_key *, struct slabdb_val *, uint8_t,
        struct xerr *);
int slabdb_put_nolock(const struct slab_key *, struct slabdb_val *,
        struct xerr *);
int slabdb_get(const struct slab_key *, struct slabdb_val *, uint32_t,
        struct xerr *);
int slabdb_get_nolock(const struct slab_key *, struct slabdb_val *,
        struct xerr *);
int slabdb_get_next_itbl(off_t *, struct xerr *);
int slabdb_loop(int(*)(const struct slab_key *, const struct slabdb_val *,
        void *), void *, struct xerr *);

int     slabdb_begin_txn(struct xerr *);
int     slabdb_commit_txn(struct xerr *);
int     slabdb_rollback_txn(struct xerr *);
ssize_t slabdb_count(struct xerr *);

#endif
